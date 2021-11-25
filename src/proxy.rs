use chrono::{DateTime, TimeZone, Utc};
use rusqlite::{params, Connection, Row};
use usiem::utilities::http_utils::OK;
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::io::Read;
use std::slice::SliceIndex;
use std::sync::{Arc, Mutex};
use std::{mem, vec};
use usiem::events::field::{SiemField, SiemIp};
use usiem::events::schema::{FieldSchema, FieldType};
use usiem::events::SiemLog;

pub struct SqliteProxy {
    storage_path: String,
    schema: FieldSchema,
    logs: BTreeMap<i64, (i64, Vec<String>)>,
    existent_dbs: BTreeSet<i64>,
    connections: Arc<Mutex<BTreeMap<i64, Connection>>>,
    commit_size: usize,
    commit_time: i64,
}

impl SqliteProxy {
    pub fn new(
        commit_size: usize,
        commit_time: i64,
        schema: FieldSchema,
        storage_path: String,
    ) -> SqliteProxy {
        let mut existent_dbs = BTreeSet::new();
        for file in fs::read_dir(&storage_path).unwrap() {
            let filename = file.unwrap();
            let pth = filename.path();
            let filename = pth
                .file_name()
                .unwrap_or(OsStr::new("foo.txt"))
                .to_string_lossy();
            if filename.ends_with(".db") && filename.starts_with("logs_") {
                let splt: Vec<&str> = filename.split(|c: char| c == '_' || c == '.').collect();
                if splt.len() == 3
                    && splt.get(0).unwrap() == &"logs"
                    && splt.get(2).unwrap() == &"db"
                {
                    existent_dbs.insert(splt.get(1).unwrap().parse::<i64>().unwrap());
                }
            }
        }
        // Initialize old dbs
        println!("DDBBs: {:?}", existent_dbs);
        let mut db = SqliteProxy {
            logs: BTreeMap::new(),
            connections: Arc::from(Mutex::from(BTreeMap::new())),
            commit_size,
            commit_time,
            schema,
            storage_path,
            existent_dbs,
        };
        db.initialize_dbs();
        db
    }

    pub fn initialize_dbs(&mut self) {
        // Last week
        match self.connections.lock() {
            Ok(mut guard) => {
                for cn_id in self.existent_dbs.iter().rev().take(7) {
                    let mut new_con =
                        match Connection::open(format!("{}/logs_{}.db", &self.storage_path, cn_id))
                        {
                            Err(_) => return,
                            Ok(cn) => cn,
                        };
                    println!("Loaded db {}", cn_id);
                    setup_schema(&mut new_con, &self.schema);
                    guard.insert(*cn_id, new_con);
                }
            }
            Err(_) => return,
        }
    }
    pub fn load_db(&mut self, cn_id: i64) {
        match self.connections.lock() {
            Ok(mut guard) => {
                let mut new_con =
                    match Connection::open(format!("{}/logs_{}.db", &self.storage_path, cn_id)) {
                        Err(_) => return,
                        Ok(cn) => cn,
                    };
                println!("Loaded db {}", cn_id);
                setup_schema(&mut new_con, &self.schema);
                guard.insert(cn_id, new_con);
            }
            Err(_) => return,
        }
    }

    pub fn search(
        &self,
        query: &str,
        from: i64,
        to: i64,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<SiemLog>, &'static str> {
        let upper = query.to_uppercase();
        if upper.contains("UPDATE")
            || upper.contains("INSERT")
            || upper.contains("DELETE")
            || upper.contains("DROP")
        {
            return Err("SQLinjection detected!");
        }
        let column_names: Vec<&str> = self.schema.fields.iter().map(|(k, _)| *k).filter(|k| k != &"message" && k != &"origin" && k != &"event_received").collect();
        let query_names: String = column_names.join("],[");
        let new_query = format!("SELECT [message],[event_received],[origin],[{}] FROM log_table WHERE event_created >= {} AND event_created <= {} AND {} LIMIT {} OFFSET {}",query_names, from, to,query, limit, offset);
        // Create search plan
        let mut query_dbs = Vec::new();
        println!("FROM {} TO {}", from, to);
        for cn_id in &self.existent_dbs {
            println!("Existent_dbs {}", cn_id);
            if cn_id >= &from && cn_id <= &to {
                query_dbs.push(cn_id);
            }
        }
        if query_dbs.len() == 0 {
            return Ok(vec![]);
        }
        match self.connections.lock() {
            Ok(mut guard) => {
                for cn_id in &query_dbs {
                    match guard.get_mut(cn_id) {
                        Some(_) => {}
                        None => {
                            let mut new_con = match Connection::open(format!(
                                "{}/logs_{}.db",
                                &self.storage_path, cn_id
                            )) {
                                Err(_) => return Err("Cannot load DB"),
                                Ok(cn) => cn,
                            };
                            println!("Loaded db {}", cn_id);
                            setup_schema(&mut new_con, &self.schema);
                            guard.insert(**cn_id, new_con);
                        }
                    }
                }
            }
            Err(_) => return Err("Cannot access sqlite db"),
        };
        let mut found_logs = Vec::with_capacity(1024);
        match self.connections.lock() {
            Ok(mut guard) => {
                for cn_id in query_dbs {
                    match guard.get_mut(cn_id) {
                        Some(con) => {
                            println!("{}", new_query);
                            let stmt = con.prepare(&new_query);
                            let mut stmt = match stmt {
                                Ok(stmt) => stmt,
                                Err(_) => return Err("Error querying sqlite"),
                            };
                            let mut rows = match stmt.query([]) {
                                Ok(rows) => rows,
                                Err(_) => return Err("Error querying sqlite"),
                            };
                            
                            while let Some(row) = rows.next().unwrap_or(None) {
                                let ip_str: String = row.get(2).unwrap();
                                let log = SiemLog::new(
                                    row.get(0).unwrap(),
                                    row.get(1).unwrap(),
                                    SiemIp::from_ip_str(&ip_str).unwrap(),
                                );
                                let log = sqlite_row_to_log(log, row, &column_names, &self.schema);
                                found_logs.push(log);
                            }
                        }
                        None => {}
                    }
                }
            }
            Err(_) => return Err("Cannot access sqlite db"),
        };
        println!("Ok logs");
        Ok(found_logs)
    }

    pub fn ingest_log(&mut self, log: &SiemLog) {
        let cn_id = from_1971_01_01(log.event_created());
        let log_sql = log_into_insert_statement(log, &self.schema);
        let now = chrono::Utc::now().timestamp_millis();
        match self.logs.get_mut(&cn_id) {
            Some((_last_update, log_list)) => {
                log_list.push(log_sql);
            }
            None => {
                self.logs.insert(cn_id, (now, vec![log_sql]));
            }
        }
    }

    pub fn close(&mut self) -> bool {
        match self.connections.lock() {
            Ok(mut guard) => {
                let mut new_map = BTreeMap::new();
                let old_con = mem::replace(&mut *guard, BTreeMap::new());
                for (key, con) in old_con.into_iter() {
                    match con.close() {
                        Ok(_) => {}
                        Err((con, _)) => {
                            new_map.insert(key, con);
                        }
                    }
                }
                if new_map.len() > 0 {
                    let _ = mem::replace(&mut *guard, new_map);
                    return false;
                } else {
                    return true;
                }
            }
            Err(_) => false,
        }
    }

    pub fn commit(&mut self) {
        let mut keys_to_insert = Vec::with_capacity(8);
        let now = chrono::Utc::now().timestamp_millis();
        for (cn_id, (last_update, log_list)) in self.logs.iter() {
            if log_list.len() > self.commit_size || now > (last_update + self.commit_time) {
                keys_to_insert.push(*cn_id);
            }
        }
        if keys_to_insert.len() > 0 {
            match self.connections.lock() {
                Ok(mut guard) => {
                    for cn_id in keys_to_insert {
                        // Create connection if does not exists
                        if !guard.contains_key(&cn_id) {
                            let mut new_con = match Connection::open(format!(
                                "{}/logs_{}.db",
                                &self.storage_path, cn_id
                            )) {
                                Err(_) => return,
                                Ok(cn) => cn,
                            };
                            println!("Instantiated db {}", cn_id);
                            self.existent_dbs.insert(cn_id);
                            setup_schema(&mut new_con, &self.schema);
                            guard.insert(cn_id, new_con);
                        }
                        match guard.get_mut(&cn_id) {
                            Some(con) => match self.logs.get_mut(&cn_id) {
                                Some((last_update, logs)) => {
                                    match insert_logs_using_conn(logs, con) {
                                        Ok(()) => {
                                            println!("Inserted {} logs", logs.len());
                                            *last_update = now;
                                            *logs = Vec::with_capacity(1024);
                                        }
                                        Err(_) => {
                                            println!("Error inserting {} logs", logs.len());
                                        }
                                    }
                                }
                                None => {}
                            },
                            None => return,
                        }
                    }
                }
                Err(_) => return,
            }
        }
    }
}

impl Clone for SqliteProxy {
    fn clone(&self) -> SqliteProxy {
        SqliteProxy {
            commit_size: self.commit_size,
            commit_time: self.commit_time,
            schema: self.schema.clone(),
            storage_path: self.storage_path.to_string(),
            logs: BTreeMap::new(),
            connections: Arc::clone(&self.connections),
            existent_dbs: self.existent_dbs.clone(),
        }
    }
}

pub fn from_1971_01_01(time: i64) -> i64 {
    let d1 = chrono::Utc.ymd(1970, 1, 1).and_hms(0, 0, 0);
    let naive =
        chrono::NaiveDateTime::from_timestamp(time / 1000 as i64, ((time % 1000) * 1000) as u32);

    let d2: DateTime<Utc> = chrono::DateTime::from_utc(naive, Utc);
    let duration = d2.signed_duration_since(d1);
    duration.num_days()
}

pub fn actual_from_1971_01_01() -> i64 {
    let d1 = chrono::Utc::now();
    let d2 = chrono::Utc.ymd(1970, 1, 1).and_hms(0, 0, 0);
    let duration = d1.signed_duration_since(d2);
    duration.num_days()
}

fn log_into_insert_statement(log: &SiemLog, schema: &FieldSchema) -> String {
    let mut statement = String::with_capacity(log.message().len() as usize * 10);
    statement.push_str("INSERT into log_table (");
    let mut values_statement = String::with_capacity(log.message().len() as usize * 10);
    for (field, _field_type) in schema.fields.iter() {
        match log.field(field) {
            Some(content) => {
                statement.push_str(&format!("[{}],", field));
                values_statement.push_str(&siem_field_to_safe_string(&content));
                values_statement.push_str(&",");
            }
            None => {
                if ![
                    "event_created",
                    "event_received",
                    "category",
                    "service",
                    "tenant",
                    "vendor",
                    "message",
                    "product",
                    "origin",
                    "tags",
                ]
                .contains(field)
                {
                    statement.push_str(&format!("[{}],", field));
                    values_statement.push_str("NULL,");
                }
            }
        }
    }
    statement.push_str("[event_created],");
    values_statement.push_str(&format!("{},", log.event_created()));
    statement.push_str("[event_received],");
    values_statement.push_str(&format!("{},", log.event_received()));
    statement.push_str("[category],");
    values_statement.push_str(&string_to_safe_string(log.category()));
    values_statement.push_str(&",");
    statement.push_str("[service],");
    values_statement.push_str(&string_to_safe_string(log.service()));
    values_statement.push_str(&",");
    statement.push_str("[tenant],");
    values_statement.push_str(&string_to_safe_string(log.tenant()));
    values_statement.push_str(&",");
    statement.push_str("[vendor],");
    values_statement.push_str(&string_to_safe_string(log.vendor()));
    values_statement.push_str(&",");
    statement.push_str("[message],");
    values_statement.push_str(&string_to_safe_string(log.message()));
    values_statement.push_str(&",");
    statement.push_str("[product],");
    values_statement.push_str(&string_to_safe_string(log.product()));
    values_statement.push_str(&",");
    statement.push_str("[origin],");
    values_statement.push_str(&siem_field_to_safe_string(&SiemField::IP(
        log.origin().clone(),
    )));
    values_statement.push_str(&",");
    statement.push_str("[tags]");
    values_statement.push_str(&string_to_safe_string(&format!("{:?}", log.tags())));
    statement.push_str(") VALUES (");
    statement.push_str(&values_statement);
    statement.push_str(")");
    return statement;
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

fn sqlite_row_to_log(
    mut log: SiemLog,
    row: &Row,
    column_names: &Vec<&str>,
    schema: &FieldSchema,
) -> SiemLog {
    let mut pos = 3;
    for name in column_names {
        if name == &"event_created" {
            log.set_event_created(row.get(pos).unwrap());
        } else if name == &"event_received" {
        } else if name == &"category" {
            log.set_category(Cow::Owned(row.get(pos).unwrap()));
        } else if name == &"service" {
            log.set_service(Cow::Owned(row.get(pos).unwrap()));
        } else if name == &"vendor" {
            log.set_vendor(Cow::Owned(row.get(pos).unwrap()));
        } else if name == &"tenant" {
            log.set_tenant(Cow::Owned(row.get(pos).unwrap()));
        } else if name == &"product" {
            log.set_product(Cow::Owned(row.get(pos).unwrap()));
        } else if name == &"tags" {
            let tags: String = row.get(pos).unwrap();
            let tags = tags.replace("{", "").replace("}", "");
            for tag in tags.split(",") {
                log.add_tag(tag);
            }
        } else if name == &"message" {
        } else if name == &"origin" {
        } else{
            match schema.get_field(name) {
                Some(field) => match field {
                    FieldType::Date(_) => {
                        match row.get(pos) {
                            Ok(val) => {
                                log.add_field(name, SiemField::Date(val));
                            },
                            Err(_) => {}
                        };
                    }
                    FieldType::Decimal(_) => {
                        match row.get(pos) {
                            Ok(val) => {
                                log.add_field(name, SiemField::F64(val));
                            },
                            Err(_) => {}
                        };
                    }
                    FieldType::Ip(_) => {
                        match row.get(pos) {
                            Ok(val ) => {
                                let val : String = val;
                                log.add_field(name, SiemField::IP(SiemIp::from_ip_str(&val).unwrap()));
                            },
                            Err(_) => {}
                        };
                    }
                    FieldType::Numeric(_) => {
                        match row.get(pos) {
                            Ok(val) => {
                                log.add_field(name, SiemField::I64(val));
                            },
                            Err(_) => {}
                        };
                    }
                    FieldType::Text(_) => {
                        match row.get(pos) {
                            Ok(val) => {
                                log.add_field(name, SiemField::Text(Cow::Owned(val)));
                            },
                            Err(_) => {}
                        };
                    }
                    FieldType::TextOptions(_, _) => {
                        match row.get(pos) {
                            Ok(val) => {
                                log.add_field(name, SiemField::Text(Cow::Owned(val)));
                            },
                            Err(_) => {}
                        };
                    },
                    _ => {}
                },
                None => {}
            }
        }
        pos += 1;
    }
    log
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
                // Text must not be indexed, only TextOptions
                statement.push_str(&format!("[{}] TEXT,", field));
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
    match conn.execute_batch(&statement) {
        Ok(_) => return,
        Err(e) => {
            println!("Error setting up schema {:?}", e);
        }
    }
}
