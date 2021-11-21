use chrono::TimeZone;
use crossbeam_channel::{Receiver, Sender, TryRecvError};
use lazy_static::lazy_static;
use rusqlite::{params, Connection};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use usiem::components::common::{
    CommandDefinition, SiemComponentCapabilities, SiemFunctionCall, SiemFunctionType, SiemMessage,
    UserRole,
};
use usiem::components::SiemComponent;
use usiem::events::field::SiemField;
use usiem::events::schema::{FieldSchema, FieldType};
use usiem::events::SiemLog;

lazy_static! {
    // TODO: use a proxy to liberate memory
    static ref CONNECTIONS: Arc<Mutex<BTreeMap<i64, Connection>>> = Arc::new(Mutex::new(BTreeMap::new()));
}

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
        initialize_database(&self.store_location, &self.schema);
        let mut logs_to_store_today: Vec<String> = Vec::new();
        let mut last_inserted_logs = chrono::Utc::now().timestamp_millis();

        loop {
            let now = chrono::Utc::now().timestamp_millis();
            match self.local_chnl_rcv.try_recv() {
                Ok(msg) => match msg {
                    SiemMessage::Command(_id, _comm_id, cmd) => match cmd {
                        SiemFunctionCall::STOP_COMPONENT(_n) => {
                            save_database();
                            return;
                        }
                        _ => {}
                    },
                    SiemMessage::Log(msg) => {
                        let log_str = log_into_insert_statement(&msg, &self.schema);
                        logs_to_store_today.push(log_str);
                    }
                    _ => {}
                },
                Err(e) => match e {
                    TryRecvError::Empty => {}
                    TryRecvError::Disconnected => return,
                },
            }
            match self.local_chnl_log_rcv.try_recv() {
                Ok(msg) => {
                    let log_str = log_into_insert_statement(&msg, &self.schema);
                    logs_to_store_today.push(log_str);
                }
                Err(e) => match e {
                    TryRecvError::Empty => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    TryRecvError::Disconnected => return,
                },
            }

            if logs_to_store_today.len() > self.commit_size
                || (now - last_inserted_logs) > self.commit_time
            {
                //Commit logs
                println!("Committing {} logs", logs_to_store_today.len());
                if logs_to_store_today.len() > 0 {
                    match insert_logs(&logs_to_store_today, &self.store_location) {
                        Ok(_) => {
                            last_inserted_logs = now;
                            logs_to_store_today = Vec::new();
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        }
                        Err(e) => {
                            println!("{}", e);
                        }
                    }
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
        }
    }
}

fn log_into_insert_statement(log: &SiemLog, schema: &FieldSchema) -> String {
    let mut statement = String::with_capacity(log.message().len() as usize * 10);
    statement.push_str("INSERT into log_table (");
    let mut values_statement = String::with_capacity(log.message().len() as usize * 10);
    for (field, _field_type) in schema.fields.iter() {
        statement.push_str(&format!("[{}],", field));
        match log.field(field) {
            Some(content) => {
                values_statement.push_str(&siem_field_to_safe_string(&content));
                values_statement.push_str(&",");
            }
            None => {
                if field == &"event_created" {
                    values_statement.push_str(&format!("{},", log.event_created()));
                } else if field == &"event_received" {
                    values_statement.push_str(&format!("{},", log.event_received()));
                } else if field == &"category" {
                    values_statement.push_str(&string_to_safe_string(log.category()));
                    values_statement.push_str(&",");
                } else if field == &"service" {
                    values_statement.push_str(&string_to_safe_string(log.service()));
                    values_statement.push_str(&",");
                } else if field == &"tenant" {
                    values_statement.push_str(&string_to_safe_string(log.tenant()));
                    values_statement.push_str(&",");
                } else if field == &"vendor" {
                    values_statement.push_str(&string_to_safe_string(log.vendor()));
                    values_statement.push_str(&",");
                } else if field == &"message" {
                    values_statement.push_str(&string_to_safe_string(log.message()));
                    values_statement.push_str(&",");
                } else if field == &"product" {
                    values_statement.push_str(&string_to_safe_string(log.product()));
                    values_statement.push_str(&",");
                } else if field == &"origin" {
                    values_statement.push_str(&siem_field_to_safe_string(&SiemField::IP(log.origin().clone())));
                    values_statement.push_str(&",");
                } else if field == &"tags" {
                    values_statement.push_str(&string_to_safe_string(&format!("{:?}",log.tags())));
                    values_statement.push_str(&",");
                } else {
                    values_statement.push_str("NULL,");
                }
            }
        }
    }
    // Remove last ","
    statement.remove(statement.len() - 1);
    values_statement.remove(values_statement.len() - 1);
    statement.push_str(") VALUES (");
    statement.push_str(&values_statement);
    statement.push_str(")");
    return statement;
}

fn insert_logs(logs: &Vec<String>, db_path: &str) -> Result<(), &'static str> {
    let today = from_1971_01_01();

    match CONNECTIONS.lock() {
        Ok(mut conn_guard) => match conn_guard.get_mut(&today) {
            Some(ref mut conn2) => {
                return insert_logs_using_conn(&logs, conn2);
            }
            None => {
                let conn = Connection::open(format!("{}/db_{}.db", db_path, today));
                match conn {
                    Ok(mut conn) => {
                        let res = insert_logs_using_conn(&logs, &mut conn);
                        conn_guard.insert(today, conn);
                        return res;
                    }
                    Err(_) => Err("Error locking DDBB"),
                }
            }
        },
        Err(_) => Err("Error locking DDBB"),
    }
}

fn insert_logs_using_conn(logs: &Vec<String>, conn: &mut Connection) -> Result<(), &'static str> {
    match conn.transaction() {
        Ok(tx) => {
            for log in logs {
                let e = tx.execute(log, params![]);
                match e {
                    Ok(_) => {}
                    Err(e) => {
                        println!("{:?}", e);
                    }
                }
            }
            match tx.commit() {
                Ok(_) => return Ok(()),
                Err(_) => Err("Error executing transaction"),
            }
        }
        Err(_) => Err("Error creating transaction"),
    }
}

fn siem_field_to_safe_string(field: &SiemField) -> String {
    match field {
        SiemField::AssetID(val) => string_to_safe_string(val),
        SiemField::Date(val) => val.to_string(),
        SiemField::Domain(val) => string_to_safe_string(val),
        SiemField::User(val) => string_to_safe_string(val),
        SiemField::F64(val) => val.to_string(),
        SiemField::U64(val) => val.to_string(),
        SiemField::U32(val) => val.to_string(),
        SiemField::I64(val) => val.to_string(),
        SiemField::IP(val) => string_to_safe_string(&val.to_string()),
        SiemField::Text(val) => string_to_safe_string(&val),
    }
}
fn string_to_safe_string(field: &str) -> String {
    // Todo: improve
    if field.contains("''") {
        if field.contains("'''") {
            format!("'{}'", field.replace("'", ""))
        } else {
            format!("'{}'", field.replace("''", "'''"))
        }
    // Fix to not have SQLi
    } else {
        format!("'{}'", field.replace("'", "''"))
    }
}

fn setup_schema(conn: &mut Connection, schema: &FieldSchema) {
    println!("Setting up schema");
    let mut statement = String::with_capacity(2048);
    let mut index_statement = String::with_capacity(2048);
    statement.push_str("CREATE TABLE IF NOT EXISTS log_table (");
    for (field, field_type) in schema.fields.iter() {
        match field_type {
            FieldType::Date(_) => {
                statement.push_str(&format!("[{}] INTEGER,", field));
                index_statement.push_str(&format!(
                    "CREATE INDEX IF NOT EXISTS idx_{} ON log_table ([{}]);",
                    field.replace(".", "_"),
                    field
                ));
            }
            FieldType::Ip(_) => {
                statement.push_str(&format!("[{}] TEXT,", field));
                index_statement.push_str(&format!(
                    "CREATE INDEX IF NOT EXISTS idx_{} ON log_table ([{}]);",
                    field.replace(".", "_"),
                    field
                ));
            }
            FieldType::Text(_) => {
                statement.push_str(&format!("[{}] TEXT,", field));
                index_statement.push_str(&format!(
                    "CREATE INDEX IF NOT EXISTS idx_{} ON log_table ([{}]);",
                    field.replace(".", "_"),
                    field
                ));
            }
            FieldType::Numeric(_) => {
                statement.push_str(&format!("[{}] NUMERIC,", field));
                index_statement.push_str(&format!(
                    "CREATE INDEX IF NOT EXISTS idx_{} ON log_table ([{}]);",
                    field.replace(".", "_"),
                    field
                ));
            }
            FieldType::Decimal(_) => {
                statement.push_str(&format!("[{}] REAL,", field));
                index_statement.push_str(&format!(
                    "CREATE INDEX IF NOT EXISTS idx_{} ON log_table ([{}]);",
                    field.replace(".", "_"),
                    field
                ));
            }
            FieldType::TextOptions(_, _) => {
                statement.push_str(&format!("[{}] TEXT,", field));
                index_statement.push_str(&format!(
                    "CREATE INDEX IF NOT EXISTS idx_{} ON log_table ([{}]);",
                    field.replace(".", "_"),
                    field
                ));
            }
        }
    }

    statement.remove(statement.len() - 1);
    statement.push_str(");");
    statement.push_str(&index_statement);
    match conn.execute(&statement, params![]) {
        Ok(_) => return,
        Err(e) => {
            println!("Error setting up schema {:?}", e);
        }
    }
}

fn initialize_database(store_location: &str, schema: &FieldSchema) {
    let today = from_1971_01_01();

    match CONNECTIONS.lock() {
        Ok(mut opt_conn) => match opt_conn.get_mut(&today) {
            Some(ref mut conn) => {
                setup_schema(conn, schema);
            }
            None => {
                let pth = format!("{}/db_{:?}.db", store_location, today);
                println!("Initialized db in {}", pth);
                let conn = Connection::open(pth);
                match conn {
                    Ok(mut conn) => {
                        setup_schema(&mut conn, schema);
                        opt_conn.insert(today, conn);
                    }
                    Err(e) => {
                        println!("{}", e);
                        panic!("Cannot create SQLite datastore!!");
                    }
                }
            }
        },
        Err(_) => {
            panic!("Cannot create SQLite datastore!!");
        }
    };
}

fn save_database() {
    match CONNECTIONS.lock() {
        Ok(mut opt_conn) => {
            opt_conn.clear();
        }
        Err(_) => {
            panic!("Cannot create SQLite datastore!!");
        }
    };
}

pub fn from_1971_01_01() -> i64 {
    let d1 = chrono::Utc::now();
    let d2 = chrono::Utc.ymd(1970, 1, 1).and_hms(0, 0, 0);
    let duration = d1.signed_duration_since(d2);
    duration.num_days()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use usiem::events::auth::{AuthEvent, AuthLoginType, LoginOutcome, RemoteLogin};
    use usiem::events::field::SiemIp;
    use usiem::events::{get_default_schema, SiemEvent};

    #[test]
    fn test_kernel_instance() {
        let mut comp = SqliteDatastore::new(
            get_default_schema(),
            "./storage_db".to_string(),
            20000,
            5000,
        );
        let local_chan = comp.local_channel();
        let (local_chnl_log_snd, local_chnl_log_rcv) = crossbeam_channel::bounded(1000);
        comp.set_log_channel(local_chnl_log_snd.clone(), local_chnl_log_rcv.clone());

        std::thread::spawn(move || comp.run());

        for _ in 1..1000000 {
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
        }
        std::thread::sleep(std::time::Duration::from_secs(10));
        let _ = local_chan.send(SiemMessage::Command(
            1,
            1,
            SiemFunctionCall::STOP_COMPONENT(Cow::Borrowed("Stop!!")),
        ));
    }
}
