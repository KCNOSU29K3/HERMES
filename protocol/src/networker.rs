
use std::collections::HashMap;

use uuid::Uuid;

pub type NetworkID = Uuid;
pub struct Networker {
    pending_dispatches: HashMap<NetworkID, Vec<u8>>}


impl Networker {
    pub fn new() -> Self {
        Self {
            pending_dispatches: HashMap::new(),
        }
    }

    pub fn queue(&mut self, network_id: NetworkID, data: Vec<u8>) {
        self.pending_dispatches.insert(network_id, data);
    }

    pub fn resolve(&mut self, network_id: NetworkID) -> Option<Vec<u8>> {
        self.pending_dispatches.remove(&network_id)
    }

    pub fn obtain(&mut self, network_id: NetworkID) -> Option<&Vec<u8>> {
        self.pending_dispatches.get(&network_id)
    }
}