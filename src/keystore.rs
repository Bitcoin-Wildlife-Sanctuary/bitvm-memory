use std::collections::HashMap;

pub enum Keystore {
    HashMap(HashMap<String, Vec<u8>>),
    REDB(redb::WriteTransaction),
}
