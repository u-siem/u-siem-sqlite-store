use crossbeam_channel::{Receiver, Sender, TryRecvError};
use std::borrow::Cow;
use usiem::components::common::{CommandDefinition, CommandError, SiemComponentCapabilities, SiemFunctionCall, SiemFunctionResponse, SiemFunctionType, SiemMessage, UserRole};
use usiem::components::SiemComponent;
use usiem::events::schema::{FieldSchema};
use usiem::events::SiemLog;

pub mod proxy;

use proxy::SqliteProxy;


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
    commit_size: usize,
    commit_time: i64,
    connections : SqliteProxy
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
                    SiemMessage::Command(_id, comm_id, cmd) => match cmd {
                        SiemFunctionCall::STOP_COMPONENT(_n) => {
                            let mut count = 0;
                            loop {
                                let exit = self.connections.close();
                                count+=1;
                                if exit {
                                    return
                                }
                                if count > 3 {
                                    println!("Cannot save all logs!!");
                                }
                            }
                        },
                        SiemFunctionCall::LOG_QUERY(query) => {
                            let msg = match self.connections.search(&query.to_string(), 0, 1000, 10000, 0) {
                                Ok(res) => {
                                    SiemMessage::Response(comm_id, SiemFunctionResponse::LOG_QUERY_RANGE(String::new(),0,0,Ok(res)))
                                },
                                Err(e) => {
                                    println!("{}",e);
                                    SiemMessage::Response(comm_id, SiemFunctionResponse::LOG_QUERY_RANGE(String::new(),0,0,Err(CommandError::SyntaxError(Cow::Borrowed("Query error")))))
                                }
                            };
                            let _ = self.kernel_sender.send(msg);
                        }
                        _ => {}
                    },
                    SiemMessage::Log(log) => {
                        log_size+=1;
                        self.connections.ingest_log(&log);
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
                        log_size+=1;
                        self.connections.ingest_log(&log);
                    },
                    Err(e) => match e {
                        TryRecvError::Empty => break,
                        TryRecvError::Disconnected => return,
                    },
                }
            }
            if now > last_commit + self.commit_time || log_size > self.commit_size {
                self.connections.commit();
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
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
            commit_size: self.commit_size.clone(),
            commit_time: self.commit_time.clone(),
            connections : self.connections.clone()
        };
        Box::from(clone)
    }

    fn set_datasets(&mut self, _datasets: Vec<usiem::components::dataset::SiemDataset>) {
        //
    }
}

impl SqliteDatastore {
    pub fn new(
        schema: FieldSchema,
        store_location: String,
        commit_size: usize,
        commit_time: i64,
    ) -> Self {
        let (local_chnl_snd, local_chnl_rcv) = crossbeam_channel::bounded(1000);
        let (local_chnl_log_snd, local_chnl_log_rcv) = crossbeam_channel::bounded(1000);
        let (kernel_sender, _) = crossbeam_channel::bounded(1);
        let proxy = SqliteProxy::new(commit_size, commit_time, schema.clone(), store_location.clone());
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
            commit_size,
            commit_time,
            connections : proxy
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use usiem::events::auth::{AuthEvent, AuthLoginType, LoginOutcome, RemoteLogin};
    use usiem::events::field::SiemIp;
    use usiem::events::{get_default_schema, SiemEvent};

    #[test]
    fn test_kernel_instance() {
        let mut comp = SqliteDatastore::new(
            get_default_schema(),
            ".".to_string(),
            10000,
            5000,
        );
        let local_chan = comp.local_channel();
        let (local_chnl_log_snd, local_chnl_log_rcv) = crossbeam_channel::bounded(5000);
        comp.set_log_channel(local_chnl_log_snd.clone(), local_chnl_log_rcv.clone());

        std::thread::spawn(move || comp.run());

        for i in 1..1000000 {
            let mut log = SiemLog::new(String::from("This is a log example ..............111111111111111111111111222222222222222222222223333333333333333333333"), chrono::Utc::now().timestamp_millis(), SiemIp::V4(0));
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
            if i%10_000 == 0 {
                println!("PUSHED {} logs", i);
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(10));
        let _ = local_chan.send(SiemMessage::Command(
            1,
            1,
            SiemFunctionCall::STOP_COMPONENT(Cow::Borrowed("Stop!!")),
        ));
    }

    #[test]
    fn test_conn_size() {
        let mut comp = SqliteDatastore::new(
            get_default_schema(),
            ".".to_string(),
            10000,
            5000,
        );
        let local_chan = comp.local_channel();
        let (local_chnl_log_snd, local_chnl_log_rcv) = crossbeam_channel::bounded(5000);
        let (kernel_snd, kernel_rcv) = crossbeam_channel::bounded(5000);
        comp.set_log_channel(local_chnl_log_snd.clone(), local_chnl_log_rcv.clone());
        comp.set_kernel_sender(kernel_snd);

        std::thread::spawn(move || comp.run());

        for i in 1..100 {
            let mut log = SiemLog::new(String::from("This is a log example ..............111111111111111111111111222222222222222222222223333333333333333333333"), i, SiemIp::V4(0));
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
            if i%10_000 == 0 {
                println!("PUSHED {} logs", i);
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(6));
        let _ = local_chan.send(SiemMessage::Command(
            1,
            1,
            SiemFunctionCall::LOG_QUERY(Cow::Borrowed("category = 'Authentication'")),
        ));
        std::thread::sleep(std::time::Duration::from_secs(2));
        match kernel_rcv.try_recv() {
            Ok(msg) => {
                match msg {
                    SiemMessage::Response(1,resp) => {
                        match resp {
                            // Todo: improve in the CORE Package...
                            SiemFunctionResponse::LOG_QUERY_RANGE(name, from, to, data) => {
                                match data {
                                    Ok(logs) => {
                                        if logs.len() == 0 {
                                            panic!("No logs returned");
                                        }
                                        for log in logs {
                                            assert_eq!(log.message(), "This is a log example ..............111111111111111111111111222222222222222222222223333333333333333333333");
                                        }
                                    },
                                    Err(_) => {
                                        panic!("Not expected response");
                                    }
                                }
                            },
                            _ => {
                                panic!("Not expected response");
                            }
                        }
                    },
                    _ => {
                        panic!("Not expected response");
                    }
                }
            },
            Err(e) => {
                panic!(e)
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
        let _ = local_chan.send(SiemMessage::Command(
            1,
            1,
            SiemFunctionCall::STOP_COMPONENT(Cow::Borrowed("Stop!!")),
        ));
    }
}
