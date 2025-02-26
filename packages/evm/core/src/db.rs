use std::{borrow::Cow, cell::RefCell, collections::BTreeMap, convert::Infallible, path::PathBuf};

use heed::{EnvFlags, EnvOpenOptions};
use rayon::slice::ParallelSliceMut;
use revm::{primitives::*, CacheState, Database, DatabaseRef, TransitionState};
use serde::{Deserialize, Serialize};

use crate::{
    receipt::{map_execution_result, TxReceipt},
    state_changes,
    state_commit::StateCommit,
    state_hash,
};

#[derive(Debug)]
struct AddressWrapper(Address);
impl heed::BytesEncode<'_> for AddressWrapper {
    type EItem = AddressWrapper;

    fn bytes_encode(item: &Self::EItem) -> Result<Cow<[u8]>, heed::BoxedError> {
        Ok(Cow::Borrowed(item.0.as_slice()))
    }
}

impl heed::BytesDecode<'_> for AddressWrapper {
    type DItem = AddressWrapper;

    fn bytes_decode(bytes: &'_ [u8]) -> Result<Self::DItem, heed::BoxedError> {
        Ok(AddressWrapper(Address::from_slice(bytes)))
    }
}

#[derive(Debug)]
struct ContractWrapper(B256);
impl heed::BytesEncode<'_> for ContractWrapper {
    type EItem = ContractWrapper;

    fn bytes_encode(item: &Self::EItem) -> Result<Cow<[u8]>, heed::BoxedError> {
        Ok(Cow::Borrowed(item.0.as_slice()))
    }
}

type HeedHeight = heed::types::U64<heed::byteorder::LittleEndian>;

#[derive(Debug)]
struct StorageEntryWrapper(U256, U256);
impl heed::BytesEncode<'_> for StorageEntryWrapper {
    type EItem = StorageEntryWrapper;

    fn bytes_encode(item: &Self::EItem) -> Result<Cow<[u8]>, heed::BoxedError> {
        let a = item.0.as_le_bytes();
        let b = item.1.as_le_bytes();

        let mut combined = Vec::with_capacity(a.len() + b.len());
        combined.extend_from_slice(a.as_ref());
        combined.extend_from_slice(b.as_ref());

        Ok(Cow::Owned(combined))
    }
}

impl heed::BytesDecode<'_> for StorageEntryWrapper {
    type DItem = StorageEntryWrapper;

    fn bytes_decode(bytes: &'_ [u8]) -> Result<Self::DItem, heed::BoxedError> {
        let a = U256::from_le_slice(&bytes[0..32]);
        let b = U256::from_le_slice(&bytes[32..]);
        Ok(StorageEntryWrapper(a, b))
    }
}

// Receipt containing only the necessary data for bootstrapping. Storing full receipts is
// responsibility of a dedicated separated database (e.g. api-sync)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TinyReceipt {
    pub gas_used: u64,
    pub success: bool,
    pub deployed_contract: Option<Address>,
}

// txHash -> receipt
#[derive(Serialize, Deserialize)]
struct CommitReceipts {
    accounts_hash: B256,
    storage_hash: B256,
    contracts_hash: B256,
    tx_receipts: HashMap<B256, TxReceipt>,
}

struct InnerStorage {
    accounts: heed::Database<AddressWrapper, heed::types::SerdeBincode<AccountInfo>>,
    commits: heed::Database<HeedHeight, heed::types::SerdeBincode<CommitReceipts>>,
    contracts: heed::Database<ContractWrapper, heed::types::SerdeBincode<Bytecode>>,
    storage: heed::Database<AddressWrapper, StorageEntryWrapper>,
}

// A (height, round) pair used to associate state with a processable unit.
#[derive(Hash, PartialEq, Eq, Debug, Default, Clone, Copy)]
pub struct CommitKey(pub u64, pub u64);

#[derive(Clone, Debug, Default)]
pub struct PendingCommit {
    pub key: CommitKey,
    pub cache: CacheState,
    pub results: BTreeMap<B256, ExecutionResult>,
    pub transitions: TransitionState,
}

#[derive(Clone, Debug)]
pub struct GenesisInfo {
    pub account: Address,
    pub deployer_account: Address,
    pub validator_contract: Address,
    pub initial_supply: U256,
}

pub struct PersistentDB {
    env: heed::Env,
    inner: RefCell<InnerStorage>,
    pub genesis_info: Option<GenesisInfo>,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("IO error")]
    IO(#[from] std::io::Error),
    #[error("heed error")]
    Heed(#[from] heed::Error),
    #[error("db full error")]
    DbFull,
    #[error("bincode error")]
    Bincode(#[from] bincode::Error),
    #[error("infallible error")]
    Infallible(#[from] Infallible),
}

impl PersistentDB {
    pub fn new(path: PathBuf) -> Result<Self, Error> {
        std::fs::create_dir_all(&path)?;

        let mut env_builder = EnvOpenOptions::new();
        env_builder.max_dbs(4);
        env_builder.map_size(1 * MAP_SIZE_UNIT);
        unsafe { env_builder.flags(EnvFlags::NO_SUB_DIR) };

        let env = unsafe { env_builder.open(path.join("evm.mdb")) }?;

        Self::new_with_env(env)
    }

    pub fn new_with_env(env: heed::Env) -> Result<Self, Error> {
        let real_disk_size = env.real_disk_size()?;
        if real_disk_size >= env.info().map_size as u64 {
            // ensure initial map size is always larger than disk size
            unsafe { env.resize(next_map_size(real_disk_size as usize))? };
        }

        let tx_env = env.clone();
        let mut wtxn = tx_env.write_txn()?;

        let accounts = env
            .create_database::<AddressWrapper, heed::types::SerdeBincode<AccountInfo>>(
                &mut wtxn,
                Some("accounts"),
            )?;
        let commits = env
            .create_database::<HeedHeight, heed::types::SerdeBincode<CommitReceipts>>(
                &mut wtxn,
                Some("commits"),
            )?;
        let contracts = env
            .create_database::<ContractWrapper, heed::types::SerdeBincode<Bytecode>>(
                &mut wtxn,
                Some("contracts"),
            )?;

        let storage = env
            .database_options()
            .types::<AddressWrapper, StorageEntryWrapper>()
            .name("storage")
            .flags(heed::DatabaseFlags::DUP_SORT)
            .create(&mut wtxn)?;

        storage
            .set_dupsort_cmp(&mut wtxn, Some(storage_dupsort_func))
            .expect("set storage dupsort");

        wtxn.commit()?;

        Ok(Self {
            env,
            inner: RefCell::new(InnerStorage {
                accounts,
                commits,
                contracts,
                storage,
            }),
            genesis_info: None,
        })
    }

    pub fn set_genesis_info(&mut self, genesis_info: GenesisInfo) {
        self.genesis_info.replace(genesis_info);
    }

    pub fn resize(&self) -> Result<(), Error> {
        let info = self.env.info();

        let current_map_size = info.map_size;

        let next_map_size = next_map_size(current_map_size);

        println!("resizing db {} -> {}", current_map_size, next_map_size);

        unsafe { self.env.resize(next_map_size)? };

        Ok(())
    }
}

const MAP_SIZE_UNIT: usize = 1024 * 1024 * 1024; // 1 GB
fn next_map_size(map_size: usize) -> usize {
    map_size / MAP_SIZE_UNIT * MAP_SIZE_UNIT + MAP_SIZE_UNIT
}

impl Database for PersistentDB {
    type Error = Error;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        <Self as DatabaseRef>::basic_ref(self, address)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        <Self as DatabaseRef>::code_by_hash_ref(self, code_hash)
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        <Self as DatabaseRef>::storage_ref(self, address, index)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        <Self as DatabaseRef>::block_hash_ref(self, number)
    }
}

impl DatabaseRef for PersistentDB {
    type Error = Error;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let txn = self.env.read_txn()?;
        let inner = self.inner.borrow();

        let basic = match inner.accounts.get(&txn, &AddressWrapper(address))? {
            Some(account) => account,
            None => match &self.genesis_info {
                Some(genesis) if genesis.account == address => revm::primitives::AccountInfo {
                    balance: genesis.initial_supply,
                    ..Default::default()
                },
                _ => AccountInfo::default(),
            },
        };

        Ok(basic.into())
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        let txn = self.env.read_txn()?;
        let inner = self.inner.borrow();

        let contract = match inner.contracts.get(&txn, &ContractWrapper(code_hash))? {
            Some(contract) => contract,
            None => Default::default(),
        };

        Ok(contract)
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let txn = self.env.read_txn()?;
        let inner = self.inner.borrow_mut();

        let mut iter = inner.storage.iter(&txn)?;

        let location = &StorageEntryWrapper(index, U256::ZERO);

        match iter.move_on_key_dup(&AddressWrapper(address), &location)? {
            Some((_, value)) if value.0 == location.0 => Ok(value.1),
            _ => Ok(U256::ZERO),
        }
    }

    fn block_hash_ref(&self, _number: u64) -> Result<B256, Self::Error> {
        todo!()
    }
}

impl PersistentDB {
    pub fn commit(&self, state_commit: &mut StateCommit) -> Result<(), Error> {
        let StateCommit {
            key,
            ref mut change_set,
            ref results,
        } = state_commit;

        match self.commit_to_db(*key, change_set, results) {
            Ok(_) => return Ok(()),
            Err(err) => match &err {
                Error::Heed(heed_err) => match heed_err {
                    heed::Error::Mdb(mdb_err) => match mdb_err {
                        heed::MdbError::MapFull => return Err(Error::DbFull),
                        _ => return Err(err),
                    },
                    _ => return Err(err),
                },
                _ => return Err(err),
            },
        }
    }

    fn commit_to_db(
        &self,
        key: CommitKey,
        change_set: &mut state_changes::StateChangeset,
        results: &BTreeMap<B256, ExecutionResult>,
    ) -> Result<(), Error> {
        assert!(!self.is_height_committed(key.0));

        let mut rwtxn = self.env.write_txn()?;
        let inner = self.inner.borrow_mut();

        let mut apply_changes = |rwtxn: &mut heed::RwTxn| -> Result<(), Error> {
            let state_changes::StateChangeset {
                ref mut accounts,
                ref mut storage,
                ref mut contracts,
            } = change_set;

            accounts.par_sort_by_key(|a| a.0);
            contracts.par_sort_by_key(|a| a.0);
            storage.par_sort_by_key(|a| a.address);

            // Update accounts
            for (address, account) in accounts.into_iter() {
                let address = AddressWrapper(*address);

                if let Some(account) = account {
                    inner.accounts.put(rwtxn, &address, &account)?;
                } else {
                    inner.accounts.delete(rwtxn, &address)?;
                }
            }
            // Update contracts
            for (hash, bytecode) in contracts.into_iter() {
                inner
                    .contracts
                    .put(rwtxn, &ContractWrapper(*hash), &bytecode)?;
            }

            // Update storage
            for state_changes::StorageChangeset {
                address,
                wipe_storage,
                ref mut storage,
            } in storage.into_iter()
            {
                if storage.is_empty() {
                    continue;
                }

                storage.par_sort_unstable_by_key(|a| a.0);

                let mut iter = inner.storage.iter_mut(rwtxn)?;
                let address = AddressWrapper(*address);

                if iter.move_on_key(&address)? {
                    if *wipe_storage {
                        // wipe all existing storage for address
                        unsafe { iter.del_current_with_flags(heed::DeleteFlags::NO_DUP_DATA)? };
                    }
                }

                for value in storage.into_iter() {
                    let new_storage_value = &StorageEntryWrapper(value.0, value.1.present_value());

                    if let Some((_, iter_value)) =
                        iter.move_on_key_dup(&address, &new_storage_value)?
                    {
                        // overwrite or delete if key matches
                        if iter_value.0 == value.0 {
                            if value.1.present_value().is_zero() {
                                let success = unsafe { iter.del_current()? };
                                assert!(success);
                            } else if value.1.present_value() != iter_value.1 {
                                unsafe {
                                    // overwrite current position of cursor
                                    let success = iter.put_current(&address, &new_storage_value)?;
                                    assert!(success);
                                }
                            } else {
                                // skip unchanged storage
                            }

                            // cursor matched existing entry, move on to next
                            continue;
                        }
                    }

                    if value.1.present_value() != U256::ZERO {
                        unsafe {
                            iter.put_current_with_options(
                                heed::PutFlags::NO_DUP_DATA,
                                &address,
                                &new_storage_value,
                            )?;
                        }
                    }
                }
            }

            // Finalize commit
            let mut tx_receipts = HashMap::new();
            for (k, result) in results {
                tx_receipts.insert(k.clone(), map_execution_result(result.clone()));
            }

            inner.commits.put(
                rwtxn,
                &key.0,
                &CommitReceipts {
                    accounts_hash: state_hash::calculate_accounts_hash(&change_set)?,
                    contracts_hash: state_hash::calculate_contracts_hash(&change_set)?,
                    storage_hash: state_hash::calculate_storage_hash(&change_set)?,
                    tx_receipts,
                },
            )?;

            Ok(())
        };

        if let Err(err) = apply_changes(&mut rwtxn) {
            rwtxn.abort();
            return Err(err.into());
        }

        rwtxn.commit()?;

        Ok(())
    }

    pub fn is_height_committed(&self, height: u64) -> bool {
        let env = self.env.clone();
        let rtxn = env.read_txn().expect("read");
        let inner = self.inner.borrow();

        inner.commits.get(&rtxn, &height).is_ok_and(|v| v.is_some())
    }

    pub fn get_committed_receipt(
        &self,
        height: u64,
        tx_hash: B256,
    ) -> Result<(bool, Option<TxReceipt>), Error> {
        let env = self.env.clone();
        let rtxn = env.read_txn().expect("read");
        let inner = self.inner.borrow();

        match inner.commits.get(&rtxn, &height)? {
            Some(receipts) => Ok((true, receipts.tx_receipts.get(&tx_hash).cloned())),
            None => Ok((false, None)),
        }
    }

    pub fn get_committed_hashes(&self, height: u64) -> Result<Option<(B256, B256, B256)>, Error> {
        let env = self.env.clone();
        let rtxn = env.read_txn().expect("read");
        let inner = self.inner.borrow();

        match inner.commits.get(&rtxn, &height)? {
            Some(receipts) => Ok(Some((
                receipts.accounts_hash,
                receipts.contracts_hash,
                receipts.storage_hash,
            ))),
            None => Ok(None),
        }
    }
}

unsafe extern "C" fn storage_dupsort_func(
    a: *const heed::MDB_val,
    b: *const heed::MDB_val,
) -> std::ffi::c_int {
    let a_data = heed::from_val(*a);
    let b_data = heed::from_val(*b);

    // The compared values are tuples of `StorageEntryWrapper` and sorted by the first tuple value (=32 byte)
    // which corresponds to the storage slot location. The second half of the tuple is ignored.
    let order = a_data[..32].cmp(&b_data[..32]);

    match order {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    }
}

impl PendingCommit {
    pub fn new(key: CommitKey) -> Self {
        Self {
            key,
            cache: Default::default(),
            results: Default::default(),
            transitions: Default::default(),
        }
    }
}

#[test]
fn test_open_db() {
    let tmp = tempfile::Builder::new()
        .prefix("evm.mdb")
        .tempdir()
        .unwrap();

    assert!(PersistentDB::new(tmp.path().to_path_buf()).is_ok());
}

#[test]
fn test_commit_changes() {
    let path = tempfile::Builder::new()
        .prefix("evm.mdb")
        .tempdir()
        .unwrap();

    let mut db = PersistentDB::new(path.path().to_path_buf()).expect("database");

    // 1) Lookup empty account
    let address = address!("bd6f65c58a46427af4b257cbe231d0ed69ed5508");
    let account = db.basic(address).expect("works").expect("account info");

    assert_eq!(
        account.code_hash,
        FixedBytes(hex!(
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        ))
    );

    // 2) Update balance for account
    let mut state = HashMap::new();

    let mut account = Account::new_not_existing();
    account.info.balance = U256::from(100);
    account.status = AccountStatus::Touched;

    let code = Bytecode::new();
    account.info.code_hash = code.hash_slow();
    account.info.code = Some(code.clone());

    let mut storage = HashMap::new();
    storage.insert(
        U256::from(1),
        revm::db::states::StorageSlot::new_changed(U256::ZERO, U256::from(1234)),
    );
    storage.insert(
        U256::from(2),
        revm::db::states::StorageSlot::new_changed(U256::ZERO, U256::from(5678)),
    );

    state.insert(
        address,
        revm::db::TransitionAccount {
            status: revm::db::AccountStatus::InMemoryChange,
            info: Some(account.info.clone()),
            previous_status: revm::db::AccountStatus::Loaded,
            previous_info: None,
            storage,
            storage_was_destroyed: false,
        },
    );

    crate::state_commit::commit_to_db(
        &mut db,
        PendingCommit {
            key: CommitKey(0, 0),
            cache: CacheState::default(),
            results: Default::default(),
            transitions: TransitionState { transitions: state },
        },
    )
    .expect("ok");

    // 3) Assert updated storage

    // Balance
    let account = db.basic(address).expect("works").expect("account info");
    assert_eq!(account.balance, U256::from(100));

    // Code
    assert_eq!(account.code_hash, code.hash_slow());
    let account_code = db.code_by_hash(code.hash_slow()).expect("code");
    assert_eq!(account_code, code);

    // Storage
    let mut account_storage = db.storage(address, U256::from(1)).expect("storage");
    assert_eq!(account_storage, U256::from(1234));

    account_storage = db.storage(address, U256::from(2)).expect("storage");
    assert_eq!(account_storage, U256::from(5678));
}

#[test]
fn test_storage() {
    let path = tempfile::Builder::new()
        .prefix("evm.mdb")
        .tempdir()
        .unwrap();

    let mut db = PersistentDB::new(path.path().to_path_buf()).expect("database");

    let address = address!("bd6f65c58a46427af4b257cbe231d0ed69ed5508");
    let mut state = HashMap::new();

    let mut account = Account::new_not_existing();
    account.status = AccountStatus::Touched;

    let mut storage = HashMap::new();

    storage.insert(
        U256::from(99),
        revm::db::states::StorageSlot::new_changed(U256::ZERO, U256::from(99)),
    );
    storage.insert(
        U256::from(1),
        revm::db::states::StorageSlot::new_changed(U256::ZERO, U256::from(1)),
    );
    storage.insert(
        U256::from(101),
        revm::db::states::StorageSlot::new_changed(U256::ZERO, U256::from(101)),
    );
    storage.insert(
        U256::from(2),
        revm::db::states::StorageSlot::new_changed(U256::ZERO, U256::from(2)),
    );
    storage.insert(
        U256::from(4),
        revm::db::states::StorageSlot::new_changed(U256::ZERO, U256::from(4)),
    );

    state.insert(
        address,
        revm::db::TransitionAccount {
            status: revm::db::AccountStatus::InMemoryChange,
            info: Some(account.info.clone()),
            previous_status: revm::db::AccountStatus::Loaded,
            previous_info: None,
            storage,
            storage_was_destroyed: false,
        },
    );

    crate::state_commit::commit_to_db(
        &mut db,
        PendingCommit {
            key: CommitKey(0, 0),
            cache: CacheState::default(),
            results: Default::default(),
            transitions: TransitionState { transitions: state },
        },
    )
    .expect("ok");

    // Assert storage is sorted

    let indexes = vec![1, 2, 4, 99, 101];

    // Storage
    for index in indexes {
        let account_storage = db.storage(address, U256::from(index)).expect("storage");
        assert_eq!(account_storage, U256::from(index));
    }
}

#[test]
fn test_storage_overwrite() {
    let path = tempfile::Builder::new()
        .prefix("evm.mdb")
        .tempdir()
        .unwrap();

    let mut db = PersistentDB::new(path.path().to_path_buf()).expect("database");

    let address = address!("bd6f65c58a46427af4b257cbe231d0ed69ed5508");
    let mut state = HashMap::new();

    let mut account = Account::new_not_existing();
    account.status = AccountStatus::Touched;

    let mut storage = HashMap::new();

    storage.insert(
        U256::from(1),
        revm::db::states::StorageSlot::new_changed(U256::ZERO, U256::from(1)),
    );
    storage.insert(
        U256::from(2),
        revm::db::states::StorageSlot::new_changed(U256::ZERO, U256::from(2)),
    );

    state.insert(
        address,
        revm::db::TransitionAccount {
            status: revm::db::AccountStatus::InMemoryChange,
            info: Some(account.info.clone()),
            previous_status: revm::db::AccountStatus::Loaded,
            previous_info: None,
            storage,
            storage_was_destroyed: false,
        },
    );

    crate::state_commit::commit_to_db(
        &mut db,
        PendingCommit {
            key: CommitKey(0, 0),
            cache: CacheState::default(),
            results: Default::default(),
            transitions: TransitionState { transitions: state },
        },
    )
    .expect("ok");

    // Assert storage
    let mut account_storage = db.storage(address, U256::from(1)).expect("storage");
    assert_eq!(account_storage, U256::from(1));
    account_storage = db.storage(address, U256::from(2)).expect("storage");
    assert_eq!(account_storage, U256::from(2));

    // Now overwrite index 1
    let mut storage = HashMap::new();
    storage.insert(
        U256::from(1),
        revm::db::states::StorageSlot::new_changed(U256::from(1), U256::from(99)),
    );

    let mut state = HashMap::new();
    state.insert(
        address,
        revm::db::TransitionAccount {
            status: revm::db::AccountStatus::Changed,
            info: Some(account.info.clone()),
            previous_status: revm::db::AccountStatus::Loaded,
            previous_info: None,
            storage,
            storage_was_destroyed: false,
        },
    );

    crate::state_commit::commit_to_db(
        &mut db,
        PendingCommit {
            key: CommitKey(1, 0),
            cache: CacheState::default(),
            results: Default::default(),
            transitions: TransitionState { transitions: state },
        },
    )
    .expect("ok");

    // Assert storage again

    // - index 1 was overwritte
    let mut account_storage = db.storage(address, U256::from(1)).expect("storage");
    assert_eq!(account_storage, U256::from(99));

    // - index 2 remains unchanged
    account_storage = db.storage(address, U256::from(2)).expect("storage");
    assert_eq!(account_storage, U256::from(2));
}

#[test]
fn test_next_map_size() {
    let input = vec![0, 1, 2, 3, 4];
    for i in input {
        let next = next_map_size(i * MAP_SIZE_UNIT);
        assert_eq!(next, (i + 1) * MAP_SIZE_UNIT);
    }
}

#[test]
fn test_resize_on_commit() {
    let create_large_commit = |height: u64, n: usize| {
        let mut buf = vec![0; 32];
        buf[0..8].copy_from_slice(&height.to_le_bytes());
        let address = Address::from_word(ethers_core::utils::keccak256(buf).into());

        let mut state = HashMap::new();

        let mut account = Account::new_not_existing();
        account.status = AccountStatus::Touched;

        let mut storage = HashMap::new();

        for i in 0..n {
            storage.insert(
                U256::from(i + 1),
                revm::db::states::StorageSlot::new_changed(U256::ZERO, U256::from(1)),
            );
        }

        state.insert(
            address,
            revm::db::TransitionAccount {
                status: revm::db::AccountStatus::InMemoryChange,
                info: Some(account.info.clone()),
                previous_status: revm::db::AccountStatus::Loaded,
                previous_info: None,
                storage,
                storage_was_destroyed: false,
            },
        );

        PendingCommit {
            key: CommitKey(height, 0),
            cache: CacheState::default(),
            results: Default::default(),
            transitions: TransitionState { transitions: state },
        }
    };

    let path = tempfile::Builder::new()
        .prefix("evm.mdb")
        .tempdir()
        .unwrap();

    let mut env_builder = EnvOpenOptions::new();
    env_builder.max_dbs(4);
    env_builder.map_size(4096 * 10); // start with very small (few kB)

    unsafe { env_builder.flags(EnvFlags::NO_SUB_DIR) };

    let env = unsafe { env_builder.open(path.path().join("evm.mdb")) }.expect("ok");

    let mut db = PersistentDB::new_with_env(env).expect("open");
    assert_eq!(db.env.info().map_size, 4096 * 10);

    // large commit to trigger a resize
    crate::state_commit::commit_to_db(&mut db, create_large_commit(0, 1024)).expect("ok");

    // increased to next MAP_SIZE_UNIT
    assert_eq!(db.env.info().map_size, MAP_SIZE_UNIT);

    // add more commits without triggering another resize
    for i in 0..10 {
        crate::state_commit::commit_to_db(&mut db, create_large_commit(i + 1, 1024)).expect("ok");
        assert_eq!(db.env.info().map_size, MAP_SIZE_UNIT);
    }

    // reopen db with initial env size should automatically resize
    drop(db);

    let env = unsafe { env_builder.open(path.path().join("evm.mdb")) }.expect("ok");
    let db = PersistentDB::new_with_env(env).expect("open");
    assert_eq!(db.env.info().map_size, MAP_SIZE_UNIT);
}
