use crossbeam_channel::{Receiver, Sender, TryRecvError};
use std::borrow::Cow;
use usiem::components::command::{
    CommandDefinition, CommandError, SiemCommandCall, SiemCommandResponse, SiemFunctionType,
};
use usiem::components::common::{SiemComponentCapabilities, SiemMessage, UserRole};
use usiem::components::SiemComponent;
use usiem::events::schema::FieldSchema;
use usiem::events::SiemLog;

pub mod proxy;

use proxy::{SqliteProxy, SqliteProxyOptions};

pub struct SqliteDatastore {
    /// Send actions to the kernel
    kernel_sender: Sender<SiemMessage>,
    /// Receive actions from other components or the kernel
    local_chnl_rcv: Receiver<SiemMessage>,
    /// Send actions to this components
    local_chnl_snd: Sender<SiemMessage>,
    local_chnl_log_snd: Sender<SiemLog>,
    local_chnl_log_rcv: Receiver<SiemLog>,
    storage: Option<Box<dyn usiem::components::common::SiemComponentStateStorage>>,
    schema: FieldSchema,
    id: u64,
    store_location: String,
    sqlite_options: SqliteProxyOptions,
    connections: SqliteProxy,
}

impl SiemComponent for SqliteDatastore {
    fn set_id(&mut self, id: u64) {
        self.id = id;
    }

    fn local_channel(&self) -> Sender<SiemMessage> {
        self.local_chnl_snd.clone()
    }

    fn set_log_channel(
        &mut self,
        sender: Sender<usiem::events::SiemLog>,
        receiver: Receiver<usiem::events::SiemLog>,
    ) {
        self.local_chnl_log_snd = sender;
        self.local_chnl_log_rcv = receiver;
    }

    fn set_kernel_sender(&mut self, sender: Sender<SiemMessage>) {
        self.kernel_sender = sender;
    }

    fn run(&mut self) {
        let mut log_size = 0;
        let mut last_commit = 0;
        loop {
            let now = chrono::Utc::now().timestamp_millis();
            match self.local_chnl_rcv.try_recv() {
                Ok(msg) => match msg {
                    SiemMessage::Command(comm_info, cmd) => match cmd {
                        SiemCommandCall::STOP_COMPONENT(_n) => {
                            let mut count = 0;
                            loop {
                                let exit = self.connections.close();
                                count += 1;
                                if exit {
                                    return;
                                }
                                if count > 5 {
                                    println!("Cannot save all logs!!");
                                    return;
                                }
                            }
                        }
                        SiemCommandCall::LOG_QUERY(query) => {
                            match &query.query_id {
                                Some(_) => {
                                    // Query over query or retrieve query info
                                    match self.connections.get_query_result(&query) {
                                        Ok((completed, log_list)) => {
                                            if completed {
                                                let _ =
                                                    self.kernel_sender.send(SiemMessage::Response(
                                                        comm_info,
                                                        SiemCommandResponse::LOG_QUERY(
                                                            query.clone(),
                                                            Ok(log_list),
                                                        ),
                                                    ));
                                            } else {
                                                let _ =
                                                    self.kernel_sender.send(SiemMessage::Response(
                                                        comm_info,
                                                        SiemCommandResponse::LOG_QUERY(
                                                            query.clone(),
                                                            Ok(vec![]),
                                                        ),
                                                    ));
                                            }
                                        }
                                        Err(err) => {
                                            let _ = self.kernel_sender.send(SiemMessage::Response(
                                                comm_info,
                                                SiemCommandResponse::LOG_QUERY(
                                                    query,
                                                    Err(CommandError::SyntaxError(Cow::Owned(
                                                        err.to_string(),
                                                    ))),
                                                ),
                                            ));
                                        }
                                    };
                                }
                                None => {
                                    match self.connections.start_query(&query) {
                                        Ok(query_res) => {
                                            let _ = self.kernel_sender.send(SiemMessage::Response(
                                                comm_info,
                                                SiemCommandResponse::LOG_QUERY(
                                                    query_res,
                                                    Ok(vec![]),
                                                ),
                                            ));
                                        }
                                        Err(err) => {
                                            let _ = self.kernel_sender.send(SiemMessage::Response(
                                                comm_info,
                                                SiemCommandResponse::LOG_QUERY(
                                                    query,
                                                    Err(CommandError::SyntaxError(Cow::Owned(
                                                        err.to_string(),
                                                    ))),
                                                ),
                                            ));
                                        }
                                    };
                                }
                            };
                        }
                        _ => {}
                    },
                    SiemMessage::Log(log) => {
                        log_size += 1;
                        self.connections.ingest_log(log);
                    }
                    _ => {}
                },
                Err(e) => match e {
                    TryRecvError::Empty => {}
                    TryRecvError::Disconnected => return,
                },
            }
            for _ in 0..100 {
                match self.local_chnl_log_rcv.try_recv() {
                    Ok(log) => {
                        log_size += 1;
                        self.connections.ingest_log(log);
                    }
                    Err(e) => match e {
                        TryRecvError::Empty => break,
                        TryRecvError::Disconnected => return,
                    },
                }
            }
            if now > last_commit + self.sqlite_options.commit_time
                || log_size > self.sqlite_options.commit_size
            {
                self.connections.commit();
                last_commit = now;
            }
            match self.connections.continue_queries() {
                Ok(_) => {}
                Err(e) => {
                    panic!("{:?}", e.to_string())
                }
            }
        }
    }

    fn set_storage(&mut self, conn: Box<dyn usiem::components::common::SiemComponentStateStorage>) {
        self.storage = Some(conn);
    }

    fn capabilities(&self) -> SiemComponentCapabilities {
        let datasets = Vec::new();
        let mut commands = Vec::new();

        let stop_component = CommandDefinition::new(
            SiemFunctionType::STOP_COMPONENT,
            Cow::Borrowed("Stop BasicParser") ,
            Cow::Borrowed("This allows stopping all indexing components.\nUse only when really needed, like when there is a bug in the parsing process.") , 
            UserRole::Administrator);
        commands.push(stop_component);
        let start_component = CommandDefinition::new(
            SiemFunctionType::START_COMPONENT, // Must be added by default by the KERNEL and only used by him
            Cow::Borrowed("Start Basic Parser"),
            Cow::Borrowed("This allows processing logs."),
            UserRole::Administrator,
        );
        commands.push(start_component);

        let search_logs = CommandDefinition::new(
            SiemFunctionType::LOG_QUERY,
            Cow::Borrowed("Search for logs"),
            Cow::Borrowed("Search for logs"),
            UserRole::Analyst,
        );
        commands.push(search_logs);

        SiemComponentCapabilities::new(
            Cow::Borrowed("SQlite datastore"),
            Cow::Borrowed("Store logs using a sqlite"),
            Cow::Borrowed(""), // No HTML
            datasets,
            commands,
            vec![],
            vec![]
        )
    }

    fn duplicate(&self) -> Box<dyn SiemComponent> {
        let (local_chnl_snd, local_chnl_rcv) = crossbeam_channel::bounded(1000);
        let clone = SqliteDatastore {
            kernel_sender: self.kernel_sender.clone(),
            local_chnl_snd,
            local_chnl_rcv,
            local_chnl_log_rcv: self.local_chnl_log_rcv.clone(),
            local_chnl_log_snd: self.local_chnl_log_snd.clone(),
            store_location: self.store_location.clone(),
            id: self.id,
            schema: self.schema.clone(),
            storage: self.storage.clone(),
            sqlite_options: self.sqlite_options.clone(),
            connections: self.connections.clone(),
        };
        Box::from(clone)
    }

    fn set_datasets(&mut self, _datasets: Vec<usiem::components::dataset::SiemDataset>) {
        //
    }
}

impl SqliteDatastore {
    pub fn new(schema: FieldSchema, store_location: String, options: SqliteProxyOptions) -> Self {
        let (local_chnl_snd, local_chnl_rcv) = crossbeam_channel::bounded(1000);
        let (local_chnl_log_snd, local_chnl_log_rcv) = crossbeam_channel::bounded(1000);
        let (kernel_sender, _) = crossbeam_channel::bounded(1);
        let proxy = SqliteProxy::new(options.clone(), schema.clone(), store_location.clone());
        SqliteDatastore {
            kernel_sender,
            local_chnl_snd,
            local_chnl_rcv,
            local_chnl_log_rcv,
            local_chnl_log_snd,
            store_location: store_location,
            id: 0,
            schema: schema,
            storage: None,
            sqlite_options: options,
            connections: proxy,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use usiem::components::command::{QueryInfo, SiemCommandHeader};
    use usiem::events::auth::{AuthEvent, AuthLoginType, LoginOutcome, RemoteLogin};
    use usiem::events::{get_default_schema, SiemEvent};

    #[test]
    fn test_sqlite_log_ingestion() {
        let mut comp = SqliteDatastore::new(
            get_default_schema(),
            ".".to_string(),
            SqliteProxyOptions::default(),
        );
        let local_chan = comp.local_channel();
        let (local_chnl_log_snd, local_chnl_log_rcv) = crossbeam_channel::bounded(5000);
        comp.set_log_channel(local_chnl_log_snd.clone(), local_chnl_log_rcv.clone());

        std::thread::spawn(move || comp.run());

        for _i in 1..12_000 {
            let mut log = SiemLog::new("This is a log example ..............111111111111111111111111222222222222222222222223333333333333333333333", chrono::Utc::now().timestamp_millis(), "localhost");
            log.set_category(Cow::Borrowed("Authentication"));
            log.set_product(Cow::Borrowed("MagicDevice001"));
            log.set_tenant(Cow::Borrowed("Default"));
            log.set_service(Cow::Borrowed("sshd"));
            log.set_vendor(Cow::Borrowed("MagicDevices"));
            log.set_event(SiemEvent::Auth(AuthEvent {
                hostname: Cow::Borrowed("hostname1"),
                outcome: LoginOutcome::FAIL,
                login_type: AuthLoginType::Remote(RemoteLogin {
                    domain: Cow::Borrowed("CNMS"),
                    source_address: Cow::Borrowed("10.10.10.10"),
                    user_name: Cow::Borrowed("cancamusa"),
                }),
            }));
            let _ = local_chnl_log_snd.send(log);
        }
        std::thread::sleep(std::time::Duration::from_secs(10));
        let _ = local_chan.send(SiemMessage::Command(
            SiemCommandHeader {
                user: String::from("None"),
                comp_id: 0,
                comm_id: 0,
            },
            SiemCommandCall::STOP_COMPONENT("Stop!!".to_string()),
        ));
    }

    #[test]
    fn test_sqlite_with_query() {
        let mut comp = SqliteDatastore::new(
            get_default_schema(),
            ".".to_string(),
            SqliteProxyOptions {
                commit_size: 10_000,
                commit_time: 5_000,
                mmap_size: 32_000_000,
            },
        );
        let local_chan = comp.local_channel();
        let (local_chnl_log_snd, local_chnl_log_rcv) = crossbeam_channel::bounded(50_000);
        let (kernel_snd, kernel_rcv) = crossbeam_channel::bounded(5000);
        comp.set_log_channel(local_chnl_log_snd.clone(), local_chnl_log_rcv.clone());
        comp.set_kernel_sender(kernel_snd);

        std::thread::spawn(move || comp.run());

        for i in 1..100_000 {
            let mut log = SiemLog::new("This is a log example ..............111111111111111111111111222222222222222222222223333333333333333333333", i, "localhost");
            log.set_category(Cow::Borrowed("Authentication"));
            log.set_product(Cow::Borrowed("MagicDevice001"));
            log.set_tenant(Cow::Borrowed("Default"));
            log.set_service(Cow::Borrowed("sshd"));
            log.set_vendor(Cow::Borrowed("MagicDevices"));
            log.set_event_created(0);
            log.set_event(SiemEvent::Auth(AuthEvent {
                hostname: Cow::Borrowed("hostname1"),
                outcome: LoginOutcome::FAIL,
                login_type: AuthLoginType::Remote(RemoteLogin {
                    domain: Cow::Borrowed("CNMS"),
                    source_address: Cow::Borrowed("10.10.10.10"),
                    user_name: Cow::Borrowed("cancamusa"),
                }),
            }));
            let _ = local_chnl_log_snd.send(log);
        }
        std::thread::sleep(std::time::Duration::from_secs(6));
        let ttl = chrono::Utc::now().timestamp_millis() + 100_000;
        let _ = local_chan.send(SiemMessage::Command(
            SiemCommandHeader {
                user: String::from("None"),
                comm_id: 1,
                comp_id: 1,
            },
            SiemCommandCall::LOG_QUERY(QueryInfo {
                user: String::from("None"),
                is_native: true,
                query_id: None,
                from: 0,
                to: 1000,
                limit: 10_000,
                offset: 0,
                ttl,
                query: "category='Authentication'".to_string(),
                fields: vec![],
            }),
        ));
        std::thread::sleep(std::time::Duration::from_secs(2));
        let query_id;
        match kernel_rcv.try_recv() {
            Ok(msg) => {
                match msg {
                    SiemMessage::Response(_, resp) => {
                        match resp {
                            // Todo: improve in the CORE Package...
                            SiemCommandResponse::LOG_QUERY(query, res) => {
                                println!("{:?}", query.query);
                                query_id = query.query_id.unwrap_or(String::new());
                                match res {
                                    Ok(logs) => {
                                        if logs.len() != 0 {
                                            panic!("Log size must be 0");
                                        }
                                    }
                                    Err(e) => {
                                        println!("{:?}", e);
                                        panic!("Not expected response");
                                    }
                                }
                            }
                            _ => {
                                panic!("Not expected response");
                            }
                        }
                    }
                    _ => {
                        panic!("Not expected response");
                    }
                }
            }
            Err(e) => {
                panic!("{:?}", e);
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
        let ttl = chrono::Utc::now().timestamp_millis() + 10_000;
        let _ = local_chan.send(SiemMessage::Command(
            SiemCommandHeader {
                user: String::from("None"),
                comm_id: 1,
                comp_id: 1,
            },
            SiemCommandCall::LOG_QUERY(QueryInfo {
                user: String::from("None"),
                is_native: true,
                query_id: Some(query_id),
                from: 0,
                to: 1000,
                limit: 100000,
                offset: 0,
                ttl,
                query: "category='Authentication'".to_string(),
                fields: vec![],
            }),
        ));
        std::thread::sleep(std::time::Duration::from_secs(4));
        match kernel_rcv.try_recv() {
            Ok(msg) => {
                match msg {
                    SiemMessage::Response(_, resp) => {
                        match resp {
                            // Todo: improve in the CORE Package...
                            SiemCommandResponse::LOG_QUERY(_query_info, res) => match res {
                                Ok(logs) => {
                                    if logs.len() == 0 {
                                        panic!("No logs returned");
                                    }
                                    println!("Returned logs: {}", logs.len());
                                    for log in logs {
                                        assert_eq!(log.get("message").unwrap().to_string(), "This is a log example ..............111111111111111111111111222222222222222222222223333333333333333333333");
                                    }
                                }
                                Err(e) => {
                                    println!("{:?}", e);
                                    panic!("Not expected response");
                                }
                            },
                            _ => {
                                panic!("Not expected response");
                            }
                        }
                    }
                    _ => {
                        panic!("Not expected response");
                    }
                }
            }
            Err(_e) => {
                panic!("No response!!!")
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
        let _ = local_chan.send(SiemMessage::Command(
            SiemCommandHeader {
                user: String::from("None"),
                comm_id: 0,
                comp_id: 0,
            },
            SiemCommandCall::STOP_COMPONENT("Stop!!".to_string()),
        ));
    }
}
