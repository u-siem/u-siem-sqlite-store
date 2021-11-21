# uSiem SQlite store
uSiem component that stores events in a sqlite database.



### Real numbers

Log indexing is fast enough for most use cases, being around 5000 logs/sec in debug mode.
A total of 1 million logs with 52 columns with an index per column has a size of 293.3 MB.

### Indexing example

```
SELECT event_created, event_received,vendor, product, service, category,tenant,tags,origin,`host.hostname`, message, `source.ip`, `user.domain`, `user.name`, `event.outcome`
FROM log_table ORDER BY event_created DESC LIMIT 10;
```

|event_created|event_received|vendor      |product       |service|category      |tenant |tags|origin |host.hostname|message                                                                                                  |source.ip  |user.domain|user.name|event.outcome|
|-------------|--------------|------------|--------------|-------|--------------|-------|----|-------|-------------|---------------------------------------------------------------------------------------------------------|-----------|-----------|---------|-------------|
|1637535361471|1637535361471 |MagicDevices|MagicDevice001|sshd   |Authentication|Default|{}  |0.0.0.0|hostname1    |This is a log example ..............111111111111111111111111222222222222222222222223333333333333333333333|10.10.10.10|CNMS       |cancamusa|FAIL         |
|1637535361471|1637535361471 |MagicDevices|MagicDevice001|sshd   |Authentication|Default|{}  |0.0.0.0|hostname1    |This is a log example ..............111111111111111111111111222222222222222222222223333333333333333333333|10.10.10.10|CNMS       |cancamusa|FAIL         |
|1637535361471|1637535361471 |MagicDevices|MagicDevice001|sshd   |Authentication|Default|{}  |0.0.0.0|hostname1    |This is a log example ..............111111111111111111111111222222222222222222222223333333333333333333333|10.10.10.10|CNMS       |cancamusa|FAIL         |
|1637535361471|1637535361471 |MagicDevices|MagicDevice001|sshd   |Authentication|Default|{}  |0.0.0.0|hostname1    |This is a log example ..............111111111111111111111111222222222222222222222223333333333333333333333|10.10.10.10|CNMS       |cancamusa|FAIL         |
|1637535361471|1637535361471 |MagicDevices|MagicDevice001|sshd   |Authentication|Default|{}  |0.0.0.0|hostname1    |This is a log example ..............111111111111111111111111222222222222222222222223333333333333333333333|10.10.10.10|CNMS       |cancamusa|FAIL         |
|1637535361471|1637535361471 |MagicDevices|MagicDevice001|sshd   |Authentication|Default|{}  |0.0.0.0|hostname1    |This is a log example ..............111111111111111111111111222222222222222222222223333333333333333333333|10.10.10.10|CNMS       |cancamusa|FAIL         |
|1637535361471|1637535361471 |MagicDevices|MagicDevice001|sshd   |Authentication|Default|{}  |0.0.0.0|hostname1    |This is a log example ..............111111111111111111111111222222222222222222222223333333333333333333333|10.10.10.10|CNMS       |cancamusa|FAIL         |
|1637535361470|1637535361470 |MagicDevices|MagicDevice001|sshd   |Authentication|Default|{}  |0.0.0.0|hostname1    |This is a log example ..............111111111111111111111111222222222222222222222223333333333333333333333|10.10.10.10|CNMS       |cancamusa|FAIL         |
|1637535361470|1637535361470 |MagicDevices|MagicDevice001|sshd   |Authentication|Default|{}  |0.0.0.0|hostname1    |This is a log example ..............111111111111111111111111222222222222222222222223333333333333333333333|10.10.10.10|CNMS       |cancamusa|FAIL         |
|1637535361470|1637535361470 |MagicDevices|MagicDevice001|sshd   |Authentication|Default|{}  |0.0.0.0|hostname1    |This is a log example ..............111111111111111111111111222222222222222222222223333333333333333333333|10.10.10.10|CNMS       |cancamusa|FAIL         |


### Example indexing logs

```rust
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

for _ in 1..100000 {
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
// Stop the component
std::thread::sleep(std::time::Duration::from_secs(10));
let _ = local_chan.send(SiemMessage::Command(
    1,
    1,
    SiemFunctionCall::STOP_COMPONENT(Cow::Borrowed("Stop!!")),
));
```