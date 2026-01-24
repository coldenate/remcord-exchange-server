use std::sync::Mutex;
use ttl_cache::TtlCache;
use std::time::Duration;
use std::collections::HashMap;

pub struct SessionManager {
    sessions: Mutex<TtlCache<String, String>>,
}

impl SessionManager {
    pub fn new(ttl: Duration) -> Self {
        SessionManager {
            sessions: Mutex::new(TtlCache::new(ttl)),
        }
    }

    pub fn add_session(&self, user_id: String, session_id: String) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(user_id, session_id);
    }

    pub fn get_session(&self, user_id: &str) -> Option<String> {
        let sessions = self.sessions.lock().unwrap();
        sessions.get(user_id).cloned()
    }

    pub fn remove_session(&self, user_id: &str) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.remove(user_id);
    }

    pub fn check_duplicate_session(&self, user_id: &str) -> bool {
        let sessions = self.sessions.lock().unwrap();
        sessions.contains_key(user_id)
    }
}
