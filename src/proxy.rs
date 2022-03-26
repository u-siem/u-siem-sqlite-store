use chrono::{DateTime, TimeZone, Utc};
use rusqlite::types::{ToSqlOutput, ValueRef};
use rusqlite::{params, Connection, Row, ToSql};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::sync::{Arc, Mutex};
use std::{mem, vec};
use usiem::components::command::QueryInfo;
use usiem::events::field::{SiemField, SiemIp};
use usiem::events::schema::{FieldSchema, FieldType};
use usiem::events::SiemLog;
use uuid::Uuid;

#[derive(Clone)]
pub struct SqliteProxyOptions {
    pub commit_size : usize,
    pub commit_time: i64,
    pub mmap_size : usize,
}
impl Default for SqliteProxyOptions {
    fn default() -> Self {
        Self {
            commit_size : 10_000,
            commit_time : 5_000,
            mmap_size : 64_000_000
        }
    }
}

pub struct SqliteProxy {
    storage_path: String,
    schema: FieldSchema,
    logs: BTreeMap<i64, (i64, Vec<SiemLog>)>,
    existent_dbs: BTreeSet<i64>,
    connections: Arc<Mutex<BTreeMap<i64, Connection>>>,
    saved_queries: Arc<Mutex<Connection>>,
    options : SqliteProxyOptions
}

impl SqliteProxy {
    pub fn new(
        options: SqliteProxyOptions,
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
        let mut saved_queries = Connection::open(format!("{}/querys.db", &storage_path))
            .expect("Cannot create QueryDB connection");
        let _ = setup_query_store(&mut saved_queries);
        // Initialize old dbs
        let mut db = SqliteProxy {
            logs: BTreeMap::new(),
            connections: Arc::from(Mutex::from(BTreeMap::new())),
            schema,
            storage_path,
            existent_dbs,
            saved_queries: Arc::from(Mutex::from(saved_queries)),
            options
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
    ) -> rusqlite::Result<Vec<SiemLog>> {
        let upper = query.to_uppercase();
        if upper.contains("UPDATE")
            || upper.contains("INSERT")
            || upper.contains("DELETE")
            || upper.contains("DROP")
        {
            return Err(rusqlite::Error::InvalidParameterName(String::from(
                "PROHIBITED QUERY",
            )));
        }
        let column_names: Vec<&str> = self
            .schema
            .fields
            .iter()
            .map(|(k, _)| *k)
            .filter(|k| k != &"message" && k != &"origin" && k != &"event_received")
            .collect();
        let query_names: String = column_names.join("],[");
        let new_query = format!("SELECT [message],[event_received],[origin],[{}] FROM log_table WHERE event_created >= {} AND event_created <= {} AND {} LIMIT {} OFFSET {}",query_names, from, to,query, limit, offset);
        // Create search plan
        let mut query_dbs = Vec::new();
        for cn_id in &self.existent_dbs {
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
                            let mut new_con = Connection::open(format!(
                                "{}/logs_{}.db",
                                &self.storage_path, cn_id
                            ))?;
                            setup_schema(&mut new_con, &self.schema);
                            guard.insert(**cn_id, new_con);
                        }
                    }
                }
            }
            Err(_) => return Err(rusqlite::Error::InvalidQuery),
        };
        let mut found_logs = Vec::with_capacity(1024);
        match self.connections.lock() {
            Ok(mut guard) => {
                for cn_id in query_dbs {
                    match guard.get_mut(cn_id) {
                        Some(con) => {
                            let mut stmt = con.prepare(&new_query)?;
                            let mut rows = stmt.query([])?;

                            while let Some(row) = rows.next().unwrap_or(None) {
                                let ip_str: String = row.get(2).unwrap();
                                let received :i64 = row.get(1).unwrap();
                                let msg : String = row.get(0).unwrap();
                                let log = SiemLog::new(
                                    msg,
                                    received,
                                    ip_str
                                );
                                let log = sqlite_row_to_log(log, row, &column_names, &self.schema)?;
                                found_logs.push(log);
                            }
                        }
                        None => {}
                    }
                }
            }
            Err(_) => return Err(rusqlite::Error::InvalidQuery),
        };
        Ok(found_logs)
    }

    pub fn ingest_log(&mut self, log: SiemLog) {
        let cn_id = from_1971_01_01(log.event_created());
        let now = chrono::Utc::now().timestamp_millis();
        match self.logs.get_mut(&cn_id) {
            Some((_last_update, log_list)) => {
                log_list.push(log);
            }
            None => {
                self.logs.insert(cn_id, (now, vec![log]));
            }
        }
    }

    pub fn close(&mut self) -> bool {
        match self.connections.lock() {
            Ok(mut guard) => {
                let mut new_map = BTreeMap::new();
                let old_con = mem::replace(&mut *guard, BTreeMap::new());
                for (key, con) in old_con.into_iter() {
                    let _ = con.execute("PRAGMA optimize", params![]);
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

    /// Create a query from a QueryInfo
    pub fn search_query_from_info(schema: &FieldSchema, query_info: &QueryInfo) -> String {
        let (table, columns) = match &query_info.query_id {
            Some(query_id) => {
                let columns = if query_info.fields.len() == 0 {
                    let column_names: Vec<&str> = schema
                        .fields
                        .iter()
                        .map(|(k, _)| *k)
                        .collect();
                    let column_names: String = column_names.join("],[");
                    format!("[{}]", column_names)
                } else {
                    format!("[{}]", query_info.fields.join("],["))
                };
                (format!("query_{}", query_id.replace("-","_")), columns)
            }
            None => {
                let column_names: Vec<&str> = schema
                    .fields
                    .iter()
                    .map(|(k, _)| *k)
                    .collect();
                let column_names: String = column_names.join("],[");
                (
                    String::from("log_table"),
                    format!("[{}]", column_names),
                )
            }
        };
        let mut where_clausule = String::new();
        if query_info.query != "" {
            where_clausule.push_str(&format!(" WHERE ({}) ", query_info.query));
        }
        if query_info.from == query_info.to && query_info.from == 0 {
            if where_clausule == "" {
                where_clausule.push_str(&format!(
                    " WHERE event_created >= {} AND event_created <= {} ",
                    query_info.from, query_info.to
                ));
            } else {
                where_clausule.push_str(&format!(
                    " AND (event_created >= {} AND event_created <= {}) ",
                    query_info.from, query_info.to
                ));
            }
        }
        match query_info.limit {
            0 => format!("SELECT {} FROM {} {}", columns, table, where_clausule),
            _ => format!(
                "SELECT {} FROM {} {} LIMIT {} OFFSET {}",
                columns, table, where_clausule, query_info.limit, query_info.offset
            ),
        }
    }

    fn update_query_statement(
        query_id: &str,
        total_rows: usize,
        rows_last_db: usize,
        finished: usize,
        last_db_id: i64,
        offset: usize,
    ) -> String {
        format!("UPDATE query_store SET total_rows = {}, rows_last_db = {}, finished = {}, last_db_id = {}, ofset = {} WHERE id = '{}'",total_rows, rows_last_db, finished,last_db_id,offset, query_id)
    }

    pub fn start_query(&mut self, query: &QueryInfo) -> rusqlite::Result<QueryInfo> {
        match self.saved_queries.lock() {
            Ok(saved_queries) => {
                let mut new_query = query.clone();
                match &query.query_id {
                    Some(_query_id) => {}
                    None => {
                        let query_id = Uuid::new_v4().to_hyphenated().to_string();
                        new_query.query_id = Some(query_id)
                    }
                };
                let _ = saved_queries.execute(
                    "INSERT INTO query_store (id, query, stored_query, columns, ttl, limite, ofset) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![new_query.query_id, query.query, query.query_id, query.fields.join(","), query.ttl, query.limit, query.offset],
                )?;
                Ok(new_query)
            }
            Err(e) => {
                Err(rusqlite::Error::InvalidParameterName(String::from(
                    "PoisonError",
                )))
            }
        }
    }

    pub fn get_query_result(
        &mut self,
        query_info: &QueryInfo,
    ) -> rusqlite::Result<(bool, Vec<BTreeMap<String, SiemField>>)> {
        let _query_id = match &query_info.query_id {
            Some(query_id) => query_id,
            None => return Err(rusqlite::Error::InvalidQuery)
        };
        let mut query_info = query_info.clone();
        query_info.query = String::new();
        let search_query = Self::search_query_from_info(&self.schema, &query_info);
        match self.saved_queries.lock() {
            Ok(mut saved_query_guard) => {
                let transaction = saved_query_guard.transaction()?;
                let mut stmt = transaction.prepare(&search_query)?;
                let mut rows = stmt.query([])?;
                let columns = self.schema.field_names();
                let mut row_list = Vec::with_capacity(1024);
                while let Some(row) = rows.next().unwrap_or(None) {
                    // TODO: Store data schema as to not use the same
                    let fields = sqlite_row_to_fields(row, &columns, &self.schema);
                    row_list.push(fields);
                }
                Ok((true,row_list))
            },
            Err(_) => Err(rusqlite::Error::InvalidQuery)
        }
    }

    /// Continue the execution of the pending queries
    pub fn continue_queries(&mut self) -> rusqlite::Result<()> {
        match self.saved_queries.lock() {
            Ok(mut saved_query_guard) => {
                // Clean old queries
                {
                    let now = chrono::Utc::now().timestamp_millis();
                    let mut list_old_queries =
                        saved_query_guard.prepare("SELECT id FROM query_store WHERE ttl < ?1")?;
                    let mut rows = list_old_queries.query(params![now])?;
                    let mut delete_old_query = String::with_capacity(1024);
                    while let Some(row) = rows.next()? {
                        let val: String = row.get(0)?;
                        delete_old_query.push_str(&format!(
                            "DROP TABLE IF EXISTS query_{};DELETE FROM query_store WHERE id = '{}';",
                            val.replace("-", "_"),
                            val
                        ));
                    }
                    saved_query_guard.execute_batch(&delete_old_query)?;
                }

                //query TEXT NOT NULL, actual_pos INTEGER DEFAULT 0, end_pos INTEGER DEFAULT 0, finished INTEGER DEFAULT 0, error
                let query_info : Option<(String,String, Option<String>,String, usize, usize,usize, usize,i64,i64, i64, i64)> = match saved_query_guard.query_row(&format!("SELECT id, query, stored_query, columns,total_rows,rows_last_db, limite, ofset, from_t, to_t, ttl, last_db_id FROM query_store WHERE finished = 0 AND stored_query IS NULL LIMIT 1"), params![], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?, row.get(10)?, row.get(11)?))
                }) {
                    Ok(query_info) => Some(query_info),
                    Err(_e) => {
                        None
                    }
                };
                let (
                    query_id,
                    query,
                    stored_query,
                    columns,
                    total_rows,
                    rows_last_db,
                    limit,
                    offset,
                    from,
                    to,
                    ttl,
                    last_db_id,
                ) = match query_info {
                    Some(query_info) => query_info,
                    None => {
                        // Query not found, search for a query over another query that has finished
                        match saved_query_guard.query_row(&format!("SELECT id, query, stored_query, total_rows, rows_last_db, limite, ofset, from_t, to_t, ttl, last_db_id FROM query_store as qs INNER JOIN query_store as qs2 WHERE qs.finished = 0 AND qs2.finished = 1 AND qs2.error = 0 AND qs.stored_query IS NOT NULL AND qs.stored_query = qs2.stored_query AND qs.id <> qs2.id LIMIT 1"), params![], |row| {
                            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?, row.get(10)?, row.get(11)?))
                        }) {
                            Ok(query_info) => query_info,
                            Err(_) => return Ok(())
                        }
                    }
                };
                let query_id_name = query_id.replace("-", "_");
                match stored_query {
                    Some(subquery_id) => {
                        // query over query
                        let subquery_id_name = subquery_id.replace("-", "_");
                        if total_rows >= limit {
                            //Close query
                            saved_query_guard.execute(
                                &Self::update_query_statement(
                                    &query_id,
                                    total_rows,
                                    total_rows,
                                    1,
                                    0,
                                    offset
                                ),
                                params![],
                            )?;
                            return Ok(());
                        }

                        // Max 10.000 per query
                        let limit = std::cmp::min(limit, 10_000);
                        let offset = offset + rows_last_db;
                        let query_info = QueryInfo {
                            user: String::new(),
                            query_id: Some(subquery_id_name.to_string()),
                            is_native: true,
                            from,
                            to,
                            limit,
                            offset,
                            query: query.to_string(),
                            ttl,
                            fields: vec![],
                        };
                        let search_query = Self::search_query_from_info(&self.schema, &query_info);
                        let transaction = saved_query_guard.transaction()?;
                        {
                            let mut stmt = transaction.prepare(&search_query)?;
                            let mut rows = stmt.query([])?;

                            let mut row_list = String::with_capacity(1024);
                            let mut number_returned_rows = 0;
                            let columns : Vec<String>  = if columns == "" {
                                self.schema.field_names()
                            }else{
                                columns.split(",").map(|r| r.to_string()).collect()
                            };
                            while let Some(row) = rows.next().unwrap_or(None) {
                                // TODO: Store data schema as to not use the same
                                let fields = sqlite_row_to_fields(row, &columns, &self.schema);
                                row_list.push_str(&fields_into_insert_statement(
                                    fields,
                                    &query_id_name,
                                    &self.schema,
                                ));
                                number_returned_rows += 1;
                                if number_returned_rows >= query_info.limit {
                                    break;
                                }
                            }
                            // Create table if does not exists fo storing the query results
                            let _ = transaction.execute(
                                &Self::create_query_result_table(&query_id_name, &self.schema),
                                params![],
                            );
                            transaction.execute_batch(&row_list)?;
                            let finished = if total_rows >= limit { 1 } else { 0 };
                            transaction.execute(
                                &Self::update_query_statement(
                                    &query_id,
                                    total_rows,
                                    rows_last_db,
                                    finished,
                                    0,
                                    offset
                                ),
                                params![],
                            )?;
                        }
                        transaction.commit()?;
                        return Ok(());
                    }
                    None => {
                        // Query over logs directly
                        // Max 10.000 per query
                        let from_db_id = from_1971_01_01(from);
                        let to_db_id = from_1971_01_01(to);
                        let available_dbs : Vec<i64> = self.existent_dbs.iter().filter(|&x| *x >= from_db_id && *x <= to_db_id).map(|x| *x).collect();
                        let actual_db_id : i64;
                        if available_dbs.contains(&last_db_id) {
                            actual_db_id = last_db_id;
                        }else{
                            actual_db_id = match available_dbs.get(0) {
                                Some(id) => *id,
                                None => {
                                    // Close query
                                    saved_query_guard.execute(
                                        &Self::update_query_statement(
                                            &query_id,
                                            total_rows,
                                            rows_last_db,
                                            1,
                                            last_db_id,
                                            offset
                                        ),
                                        params![],
                                    )?;
                                    return Ok(());
                                }
                            }
                        }

                        let new_limit = std::cmp::min(limit - total_rows, 10_000);
                        // offset must be reduced each DB change
                        let query_info = QueryInfo {
                            user: String::new(),
                            query_id: None,
                            is_native: true,
                            from,
                            to,
                            limit : new_limit,
                            offset : rows_last_db,
                            query: query.to_string(),
                            ttl,
                            fields: vec![],
                        };
                        let search_query = Self::search_query_from_info(&self.schema, &query_info);
                        let transaction = saved_query_guard.transaction()?;
                        match self.connections.lock() {
                            Ok(mut conn_guard) => {
                                match conn_guard.get_mut(&actual_db_id) {
                                    Some(actual_db_conn) => {
                                        let mut stmt = actual_db_conn.prepare(&search_query)?;
                                        let mut rows = stmt.query([])?;
                                        
                                        let mut number_returned_rows = 0;
                                        let columns : Vec<String>  = if columns == "" {
                                            self.schema.field_names()
                                        }else{
                                            columns.split(",").map(|r| r.to_string()).collect()
                                        };
                                        // TODO: Store data schema as to not use the same
                                        transaction.execute(
                                            &Self::create_query_result_table(&query_id_name, &self.schema),
                                            params![],
                                        )?;
                                        let schema_statement = schema_into_statement(&self.schema,&format!("query_{}",&query_id_name));
                                        let mut schema_statement = transaction.prepare(&schema_statement)?;
                                        while let Some(row) = rows.next().unwrap_or(None) {
                                            
                                            if rows_last_db + number_returned_rows > offset {
                                                let fields = sqlite_row_to_fields(row, &columns, &self.schema);
                                                let mut sql_field_list = Vec::with_capacity(fields.len());
                                                for (field, _field_type) in self.schema.fields.iter() {
                                                    let siem_field = fields.get(*field);
                                                    sql_field_list.push(SqliteSiemField::new(siem_field));
                                                }
                                                schema_statement.execute(rusqlite::params_from_iter(sql_field_list.iter()))?;
                                            }
                                            number_returned_rows += 1;
                                        }
                                        schema_statement.finalize()?;
                                        
                                        let mut query_finished = 0;

                                        let (new_total_rows, new_rows_last_db, new_last_db_id, new_offset) = if number_returned_rows < new_limit {
                                            // Must change DB
                                            let next_db_id = match available_dbs.iter().find(|&r| *r > actual_db_id) {
                                                Some(id) => *id,
                                                None => {
                                                    query_finished = 1;
                                                    0
                                                }
                                            };
                                            // Calculate query offsets for the new DB
                                            (total_rows + number_returned_rows,0, next_db_id, std::cmp::max(offset - (rows_last_db + number_returned_rows), 0) as usize)
                                        }else {
                                            (total_rows + number_returned_rows, rows_last_db + number_returned_rows, last_db_id, offset)
                                        };
            
                                        let query_finished = if query_finished == 1 || new_total_rows >= limit || (last_db_id == to_db_id && number_returned_rows < new_limit) { 1 } else { 0 };
                                        let update_query = Self::update_query_statement(
                                            &query_id,
                                            new_total_rows,
                                            new_rows_last_db,
                                            query_finished,
                                            new_last_db_id,
                                            new_offset
                                        );
                                        match transaction.execute(
                                            &update_query,
                                            params![]
                                        ){
                                            Ok(_rows) => {},
                                            Err(_e) =>{

                                            }
                                        }
                                    },
                                    None => {
                                        let mut finished = 0;
                                        // Next connection and close if there are no more
                                        let next_db_id = match available_dbs.iter().find(|&r| *r > actual_db_id) {
                                            Some(id) => *id,
                                            None => {
                                                finished = 1;
                                                0
                                            }
                                        };
                                        transaction.execute(
                                            &Self::update_query_statement(
                                                &query_id_name,
                                                total_rows,
                                                rows_last_db,
                                                finished,
                                                next_db_id,
                                                offset
                                            ),
                                            params![]
                                        )?;
                                    }
                                }
                            },
                            Err(_e) => {
                                //TODO: Poison error in mutex...
                            }
                        };
                        transaction.commit()?;
                        return Ok(());
                    }
                }
            }
            Err(_) => {}
        };
        Ok(())
    }

    fn create_query_result_table(name: &str, schema: &FieldSchema) -> String {
        let mut statement = String::with_capacity(2048);
        statement.push_str(&format!("CREATE TABLE IF NOT EXISTS query_{} (", name));
        for (field, field_type) in schema.fields.iter() {
            match field_type {
                FieldType::Date(_) => {
                    statement.push_str(&format!("[{}] INTEGER,", field));
                }
                FieldType::Ip(_) => {
                    statement.push_str(&format!("[{}] TEXT,", field));
                }
                FieldType::Text(_) => {
                    // Text must not be indexed, only TextOptions
                    statement.push_str(&format!("[{}] TEXT,", field));
                }
                FieldType::Numeric(_) => {
                    statement.push_str(&format!("[{}] NUMERIC,", field));
                }
                FieldType::Decimal(_) => {
                    statement.push_str(&format!("[{}] REAL,", field));
                }
                FieldType::TextOptions(_, _) => {
                    statement.push_str(&format!("[{}] TEXT,", field));
                }
            }
        }

        statement.remove(statement.len() - 1);
        statement.push_str(");");
        return statement;
    }

    pub fn commit(&mut self) {
        let mut keys_to_insert = Vec::with_capacity(8);
        let now = chrono::Utc::now().timestamp_millis();
        for (cn_id, (last_update, log_list)) in self.logs.iter() {
            if log_list.len() > self.options.commit_size || now > (last_update + self.options.commit_time) {
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
                            let optimize_db = !self.existent_dbs.contains(&cn_id);
                            self.existent_dbs.insert(cn_id);
                            setup_schema(&mut new_con, &self.schema);
                            // Performance tunning with pragma
                            if optimize_db {
                                let _ = new_con.pragma_update(None, &"journal_mode", &"WAL");
                                let _ = new_con.pragma_update(None, &"synchronous", &"normal");
                                let _ = new_con.pragma_update(None, &"temp_store", &"memory");
                                let _ = new_con.pragma_update(None, &"mmap_size", 30000000000 as i64);
                                let _ = new_con.pragma_update(None, &"page_size", 32768 as i64);
                            }
                            
                            guard.insert(cn_id, new_con);
                        }
                        match guard.get_mut(&cn_id) {
                            Some(con) => match self.logs.get_mut(&cn_id) {
                                Some((last_update, logs)) => {
                                    match insert_logs_using_statement(
                                        logs,
                                        &self.schema,
                                        con,
                                        "log_table",
                                    ) {
                                        Ok(()) => {
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
            options : self.options.clone(),
            schema: self.schema.clone(),
            storage_path: self.storage_path.to_string(),
            logs: BTreeMap::new(),
            connections: Arc::clone(&self.connections),
            existent_dbs: self.existent_dbs.clone(),
            saved_queries: Arc::clone(&self.saved_queries),
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

/// Save the query result in another table
fn fields_into_insert_statement(
    fields: BTreeMap<String, SiemField>,
    table_name: &str,
    schema: &FieldSchema,
) -> String {
    let mut statement = String::with_capacity(1024);
    statement.push_str(&format!("INSERT into query_{} (", table_name));
    for (name,_field) in fields.iter() {
        if schema.get_field(name).is_some(){
            statement.push_str(name);
            statement.push_str(",");
        }
    }
    statement.remove(statement.len()-1);
    statement.push_str(") VALUES (");
    for (name,field) in fields.iter() {
        match schema.get_field(name) {
            // TODO: Sqli protection
            Some(tipe) => match tipe {
                FieldType::Date(_) => {
                    statement.push_str(&format!("'{}',",field));
                }
                FieldType::Decimal(_) => {
                    statement.push_str(&format!("{},",field));
                }
                FieldType::Ip(_) => {
                    statement.push_str(&format!("'{}',",field));
                }
                FieldType::Numeric(_) => {
                    statement.push_str(&format!("{},",field));
                }
                FieldType::Text(_) => {
                    statement.push_str(&format!("'{}',",field));
                }
                FieldType::TextOptions(_, _) => {
                    statement.push_str(&format!("'{}',",field));
                }
            },
            None => {}
        }
    }
    statement.remove(statement.len()-1);
    statement.push_str(");");
    statement
}

fn schema_into_statement(schema: &FieldSchema, table_name: &str) -> String {
    let mut statement = String::with_capacity(schema.fields.len() as usize * 10);
    statement.push_str(&format!("INSERT into {} (", table_name));
    let mut values_statement = String::with_capacity(schema.fields.len() as usize * 10);
    let mut field_indx = 0;
    for (field, _field_type) in schema.fields.iter() {
        statement.push_str(&format!("[{}],", field));
        values_statement.push_str(&format!("${},", field_indx));
        field_indx += 1;
    }
    //Remove last ","
    values_statement.remove(values_statement.len() - 1);
    statement.remove(statement.len() - 1);
    statement.push_str(") VALUES (");
    statement.push_str(&values_statement);
    statement.push_str(")");
    return statement;
}
/* 
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
*/
fn insert_logs_using_statement(
    logs: &Vec<SiemLog>,
    schema: &FieldSchema,
    conn: &mut Connection,
    table_name: &str,
) -> rusqlite::Result<()> {
    let conn = conn.transaction()?;
    let stmt = schema_into_statement(schema, table_name);
    let mut stmt = conn.prepare(&stmt)?;
    for log in logs {
        let mut sql_field_list = Vec::with_capacity(schema.fields.len());
        for (field, _field_type) in schema.fields.iter() {
            let siem_field = log.field(field);
            sql_field_list.push(SqliteSiemField::new(siem_field));
        }
        stmt.execute(rusqlite::params_from_iter(sql_field_list.iter()))?;
    }
    drop(stmt);
    conn.commit()?;
    Ok(())
}
/* 
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
}*/
/// Transforms a SQL Row to a SiemLog
fn sqlite_row_to_log(
    mut log: SiemLog,
    row: &Row,
    column_names: &Vec<&str>,
    schema: &FieldSchema,
) -> rusqlite::Result<SiemLog> {
    let mut pos = 3;
    for name in column_names {
        if name == &"event_created" {
            log.set_event_created(row.get(pos)?);
        } else if name == &"event_received" {
        } else if name == &"category" {
            log.set_category(Cow::Owned(row.get(pos)?));
        } else if name == &"service" {
            log.set_service(Cow::Owned(row.get(pos)?));
        } else if name == &"vendor" {
            log.set_vendor(Cow::Owned(row.get(pos)?));
        } else if name == &"tenant" {
            log.set_tenant(Cow::Owned(row.get(pos)?));
        } else if name == &"product" {
            log.set_product(Cow::Owned(row.get(pos)?));
        } else if name == &"tags" {
            let tags: String = row.get(pos)?;
            let tags = tags.replace("{", "").replace("}", "");
            for tag in tags.split(",") {
                log.add_tag(tag);
            }
        } else if name == &"message" {
        } else if name == &"origin" {
        } else {
            match schema.get_field(name) {
                Some(field) => match field {
                    FieldType::Date(_) => {
                        match row.get(pos) {
                            Ok(val) => {
                                log.add_field(name, SiemField::Date(val));
                            }
                            Err(_) => {}
                        };
                    }
                    FieldType::Decimal(_) => {
                        match row.get(pos) {
                            Ok(val) => {
                                log.add_field(name, SiemField::F64(val));
                            }
                            Err(_) => {}
                        };
                    }
                    FieldType::Ip(_) => {
                        match row.get(pos) {
                            Ok(val) => {
                                let val: String = val;
                                log.add_field(
                                    name,
                                    SiemField::IP(SiemIp::from_ip_str(&val).unwrap()),
                                );
                            }
                            Err(_) => {}
                        };
                    }
                    FieldType::Numeric(_) => {
                        match row.get(pos) {
                            Ok(val) => {
                                log.add_field(name, SiemField::I64(val));
                            }
                            Err(_) => {}
                        };
                    }
                    FieldType::Text(_) => {
                        match row.get(pos) {
                            Ok(val) => {
                                log.add_field(name, SiemField::Text(Cow::Owned(val)));
                            }
                            Err(_) => {}
                        };
                    }
                    FieldType::TextOptions(_, _) => {
                        match row.get(pos) {
                            Ok(val) => {
                                log.add_field(name, SiemField::Text(Cow::Owned(val)));
                            }
                            Err(_) => {}
                        };
                    }
                },
                None => {}
            }
        }
        pos += 1;
    }
    Ok(log)
}
/// Transforms a SQL Row into a BTreeMap
fn sqlite_row_to_fields(
    row: &Row,
    column_names: &Vec<String>,
    schema: &FieldSchema,
) -> BTreeMap<String, SiemField> {
    let mut to_ret = BTreeMap::new();
    let mut pos = 0;
    for name in column_names {
        match schema.get_field(name) {
            Some(field) => match field {
                FieldType::Date(_) => {
                    match row.get(pos) {
                        Ok(val) => {
                            to_ret.insert(name.to_string(), SiemField::Date(val));
                        }
                        Err(_) => {}
                    };
                }
                FieldType::Decimal(_) => {
                    match row.get(pos) {
                        Ok(val) => {
                            to_ret.insert(name.to_string(), SiemField::F64(val));
                        }
                        Err(_) => {}
                    };
                }
                FieldType::Ip(_) => {
                    match row.get(pos) {
                        Ok(val ) => {
                            
                            let val: String = val;
                            match SiemIp::from_ip_str(&val) {
                                Ok(v) => {
                                    to_ret.insert(
                                        name.to_string(),
                                        SiemField::IP(v),
                                    );
                                },
                                Err(_) => {}
                            }
                        }
                        Err(_) => {}
                    };
                }
                FieldType::Numeric(_) => {
                    match row.get(pos) {
                        Ok(val) => {
                            to_ret.insert(name.to_string(), SiemField::I64(val));
                        }
                        Err(_) => {}
                    };
                }
                FieldType::Text(_) => {
                    match row.get(pos) {
                        Ok(val) => {
                            to_ret.insert(name.to_string(), SiemField::Text(Cow::Owned(val)));
                        }
                        Err(_) => {}
                    };
                }
                FieldType::TextOptions(_, _) => {
                    match row.get(pos) {
                        Ok(val) => {
                            to_ret.insert(name.to_string(), SiemField::Text(Cow::Owned(val)));
                        }
                        Err(_) => {}
                    };
                }
            },
            None => {}
        }
        pos += 1;
    }
    to_ret
}
/* 
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
}*/
/* 
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
*/
fn setup_query_store(conn: &mut Connection) -> rusqlite::Result<()> {
    conn.execute_batch("CREATE TABLE IF NOT EXISTS query_store (id TEXT PRIMARY KEY, columns TEXT NOT NULL, query TEXT NOT NULL, stored_query TEXT DEFAULT NULL, total_rows INTEGER DEFAULT 0, last_db_id INTEGER DEFAULT 0, rows_last_db  INTEGER DEFAULT 0, finished INTEGER DEFAULT 0, error INTEGER DEFAULT 0, ttl INTEGER NOT NULL, from_t INTEGER DEFAULT 0, to_t INTEGER DEFAULT 0, limite INTEGER DEFAULT 0, ofset INTEGER DEFAULT 0);")?;
    Ok(())
}
/* 
fn get_pending_queries(conn: &mut Connection) -> Vec<String> {
    let stmt = conn.prepare("SELECT id FROM query_store WHERE finished = 0");
    match stmt {
        Ok(mut stmt) => {
            let mut rows = match stmt.query([]) {
                Ok(rows) => rows,
                Err(_) => return vec![],
            };
            let mut to_ret = Vec::with_capacity(1024);
            while let Some(row) = rows.next().unwrap_or(None) {
                match row.get(1) {
                    Ok(ip_str) => {
                        to_ret.push(ip_str);
                    }
                    Err(_) => {}
                }
            }
            to_ret
        }
        Err(_) => vec![],
    }
}
*/
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

pub struct SqliteSiemField<'f> {
    field: Option<&'f SiemField>,
}
impl<'f> SqliteSiemField<'f> {
    pub fn new(field: Option<&'f SiemField>) -> Self {
        SqliteSiemField { field }
    }
}
impl<'f> ToSql for SqliteSiemField<'f> {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'f>> {
        match self.field {
            Some(field) => match field {
                SiemField::AssetID(val) => Ok(ToSqlOutput::Borrowed(ValueRef::from(&val[..]))),
                SiemField::Date(val) => {
                    Ok(ToSqlOutput::Owned(rusqlite::types::Value::Integer(*val)))
                }
                SiemField::Domain(val) => Ok(ToSqlOutput::Borrowed(ValueRef::from(&val[..]))),
                SiemField::User(val) => Ok(ToSqlOutput::Borrowed(ValueRef::from(&val[..]))),
                SiemField::F64(val) => Ok(ToSqlOutput::Owned(rusqlite::types::Value::Real(*val))),
                SiemField::U64(val) => Ok(ToSqlOutput::Owned(rusqlite::types::Value::Integer(
                    *val as i64,
                ))),
                SiemField::U32(val) => Ok(ToSqlOutput::Owned(rusqlite::types::Value::Integer(
                    *val as i64,
                ))),
                SiemField::I64(val) => Ok(ToSqlOutput::Owned(rusqlite::types::Value::Integer(
                    *val as i64,
                ))),
                SiemField::IP(val) => Ok(ToSqlOutput::Owned(rusqlite::types::Value::Text(
                    val.to_string(),
                ))),
                SiemField::Text(val) => Ok(ToSqlOutput::Borrowed(ValueRef::from(&val[..]))),
            },
            None => Ok(ToSqlOutput::Owned(rusqlite::types::Value::Null)),
        }
    }
}
