//! Второй контроллер домена: роль реплики, состояние синхронизации и запрет записи на слейве.
//!
//! `hprop`/`hpropd` умеют переслать базу — это транспорт. Что делает контроллер домена
//! контроллером, здесь: **кто я в репликации**, **когда последний раз база сходилась** и **что
//! происходит с записью, пришедшей на слейв**.
//!
//! # Модель консистентности — одна точка записи
//!
//! Запись идёт только на мастере. Слейв обслуживает `AS-REQ`/`TGS-REQ`/`kpasswd` из своей копии,
//! но `kadmin` на нём обязан отказать, и отказ этот — не «ошибка базы», а решение реалма: запись
//! на слейве разошлась бы с мастером на время до следующего пуша, а ключи, выданные на двух
//! контроллерах врозь, не сходятся никогда — `kvno` у них независимые.
//!
//! Поэтому слейв строится не «такой же, но осторожный», а с [`ReadOnly`] поверх своего хранилища.
//! Обёртка отказывает в пяти пишущих операциях [`Hdb`] и считает отказы: счётчик — то, что
//! показывает мониторингу, что кто-то пытается писать не туда.
//!
//! # Расхождение `kvno`
//!
//! Пуш, пришедший позже своего поколения ключей, откатил бы запись: клиент, уже получивший тикет
//! с `kvno` 5, после такого пуша получил бы `KDC_ERR_BAD_INTEGRITY` на всех последующих. [`ReplicaTarget`]
//! поэтому сравнивает `kvno` пришедшей записи с тем, что лежит в целевой базе, и запись старше
//! текущей **не применяет**, считая её отдельным числом в [`SyncState::stale`]. Молча пропустить её
//! нельзя: расхождение — факт, который оператор должен увидеть, а не догадаться о нём по жалобам.
//!
//! Одинаковый `kvno` применяется: это то же поколение, и повторный пуш того же состояния —
//! нормальный случай (мастер переслал базу дважды). Отличить «то же состояние» от «те же kvno,
//! но другие ключи» здесь нечем, и выбирать в пользу отказа значило бы ломать восстановление
//! после аварии, когда переслать надо ровно то же поколение.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::error::{Error, Result};
use crate::hdb::{Hdb, HdbEntry, Policy};
use crate::name::Principal;

use super::{PropagationTarget, Summary};

/// Роль этого контроллера в репликации.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Один контроллер. Пишет сам, никого не реплицирует и пуша не принимает.
    Standalone,
    /// Мастер: единственная точка записи, источник пушей.
    Master,
    /// Слейв: только чтение, принимает пуши мастера.
    Slave,
}

impl Role {
    /// Может ли этот контроллер писать в свою базу.
    pub fn accepts_writes(self) -> bool {
        !matches!(self, Role::Slave)
    }

    /// Принимает ли он пуш от мастера.
    pub fn accepts_propagation(self) -> bool {
        matches!(self, Role::Slave)
    }

    /// Как роль называется в отчёте и в отказе.
    pub fn name(self) -> &'static str {
        match self {
            Role::Standalone => "standalone",
            Role::Master => "master",
            Role::Slave => "slave",
        }
    }
}

/// Что известно о последней сошедшейся репликации.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SyncState {
    /// Когда база была принята, по часам этого контроллера.
    pub at: i64,
    /// Сколько записей применено.
    pub entries: usize,
    /// Сколько записей пропущено как старше текущих.
    ///
    /// Не ноль — это сигнал: мастер прислал поколение, которое здесь уже перекрыто. Причина
    /// обычно одна из двух: пуш пришёл дважды с разными снимками, или на слейве кто-то писал
    /// в обход (что [`ReadOnly`] и должен был не дать).
    pub stale: usize,
    /// Откуда пришёл пуш, если известно: имя хоста мастера.
    pub master: Option<String>,
}

/// Роль и состояние синхронизации — шов, который видит мониторинг.
///
/// Отдельный трейт, а не поля KDC: состояние репликации читает не протокол, а наблюдатель, и
/// KDC, знающий про репликацию, отвечал бы за неё. Здесь же слейв остаётся обычным KDC над
/// [`Hdb`], а всё, что делает его слейвом, живёт в этом модуле.
pub trait Replica: std::fmt::Debug + Send + Sync {
    /// Роль этого контроллера.
    fn role(&self) -> Role;

    /// Последняя сошедшаяся репликация, если она была.
    fn last_sync(&self) -> Option<SyncState>;

    /// Записать, что база сошлась.
    fn record(&self, sync: SyncState);

    /// Записать попытку записи, которую роль не разрешает.
    ///
    /// Причина — не для лога здесь (лог ведёт вызывающий), а чтобы [`Self::refused_writes`]
    /// отвечал на вопрос «пытаются ли писать не туда» одним числом.
    fn refused(&self, what: &str);

    /// Сколько раз роль отказала в записи.
    fn refused_writes(&self) -> u64;

    /// Разрешена ли здесь запись.
    fn writable(&self) -> bool {
        self.role().accepts_writes()
    }
}

/// Один контроллер: пишет сам, репликации нет.
#[derive(Debug, Default, Clone, Copy)]
pub struct Standalone;

impl Replica for Standalone {
    fn role(&self) -> Role {
        Role::Standalone
    }

    fn last_sync(&self) -> Option<SyncState> {
        None
    }

    fn record(&self, _sync: SyncState) {
        // Мастеру нечего записывать: база, которую он раздаёт, и есть его собственная.
    }

    fn refused(&self, _what: &str) {
        // Писать здесь можно, поэтому отказов не бывает.
    }

    fn refused_writes(&self) -> u64 {
        0
    }
}

/// Мастер: единственная точка записи.
///
/// Синхронизацию не ведёт — вести её должен слейв, а мастер знает о пуше только то, что его
/// отправил. Если [`Self::record`] всё же вызван, это ошибка вызывающего, и она видна по
/// [`Self::last_sync`], который остаётся `None`: молча записать чужое состояние хуже.
#[derive(Debug, Default, Clone, Copy)]
pub struct Master;

impl Replica for Master {
    fn role(&self) -> Role {
        Role::Master
    }

    fn last_sync(&self) -> Option<SyncState> {
        None
    }

    fn record(&self, _sync: SyncState) {}

    fn refused(&self, _what: &str) {}

    fn refused_writes(&self) -> u64 {
        0
    }
}

/// Слейв: только чтение, принимает пуши.
#[derive(Debug, Default)]
pub struct Slave {
    last: Mutex<Option<SyncState>>,
    refused: AtomicU64,
}

impl Slave {
    /// Слейв, который ещё ничего не принял.
    pub fn new() -> Slave {
        Slave::default()
    }
}

impl Replica for Slave {
    fn role(&self) -> Role {
        Role::Slave
    }

    fn last_sync(&self) -> Option<SyncState> {
        // `Mutex`, а не `RwLock`: запись сюда случается раз на пуш, чтение — из мониторинга, и
        // спор за замок здесь не тот, ради которого стоит усложнять.
        self.last.lock().ok().and_then(|g| g.clone())
    }

    fn record(&self, sync: SyncState) {
        if let Ok(mut guard) = self.last.lock() {
            *guard = Some(sync);
        }
    }

    fn refused(&self, _what: &str) {
        self.refused.fetch_add(1, Ordering::Relaxed);
    }

    fn refused_writes(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }
}

/// Хранилище роли, которая не пишет: отказывает во всём пишущем и пропускает чтение.
///
/// Ставится на слейве поверх его собственного [`Hdb`]. Отказ — [`Error::Forbidden`], а не
/// `Error::Hdb`: «эта база не принимает запись» — решение реалма, и оператор, увидев «Hdb», пошёл
/// бы искать дефект в хранилище.
#[derive(Debug)]
pub struct ReadOnly<H: Hdb> {
    inner: H,
    replica: Arc<dyn Replica>,
}

impl<H: Hdb> ReadOnly<H> {
    /// `inner`, доступное только на чтение, с отказами, считаемыми в `replica`.
    pub fn new(inner: H, replica: Arc<dyn Replica>) -> ReadOnly<H> {
        ReadOnly { inner, replica }
    }

    /// Хранилище под обёрткой.
    pub fn inner(&self) -> &H {
        &self.inner
    }

    /// Отказ в записи, с причиной, называющей роль и место, где писать.
    fn refuse(&self, what: &str) -> Error {
        self.replica.refused(what);
        let role = self.replica.role();
        Error::Forbidden(format!(
            "this realm's {} controller is read-only: {what} belongs on the master, and the \
             replication brings it here",
            role.name()
        ))
    }
}

impl<H: Hdb> Hdb for ReadOnly<H> {
    fn fetch(&self, principal: &Principal) -> Result<Option<HdbEntry>> {
        self.inner.fetch(principal)
    }

    fn fetch_for_service(&self, service: &Principal) -> Result<Option<HdbEntry>> {
        self.inner.fetch_for_service(service)
    }

    fn store(&self, _entry: HdbEntry) -> Result<()> {
        Err(self.refuse("storing an entry"))
    }

    fn remove(&self, _principal: &Principal) -> Result<bool> {
        Err(self.refuse("removing an entry"))
    }

    fn rename(&self, _from: &Principal, _to: &Principal) -> Result<()> {
        Err(self.refuse("renaming an entry"))
    }

    fn first(&self) -> Result<Option<Principal>> {
        self.inner.first()
    }

    fn next(&self, after: &Principal) -> Result<Option<Principal>> {
        self.inner.next(after)
    }

    fn fetch_policy(&self, name: &str) -> Result<Option<Policy>> {
        self.inner.fetch_policy(name)
    }

    fn store_policy(&self, _policy: Policy) -> Result<()> {
        Err(self.refuse("storing a policy"))
    }

    fn remove_policy(&self, _name: &str) -> Result<bool> {
        Err(self.refuse("removing a policy"))
    }
}

/// Приём пуша на слейве: применяет записи, не откатывая `kvno`, и квитирует итог в [`Replica`].
///
/// Оборачивает любой [`PropagationTarget`] — `StagedHdb` на стенде, `FileTarget` в бою, — поэтому
/// защита от отката и учёт не зависят от того, куда именно пишется база.
#[derive(Debug)]
pub struct ReplicaTarget<T: PropagationTarget> {
    inner: T,
    /// База, с которой сравнивается `kvno`: та, что слейв уже отдаёт клиентам.
    live: Arc<dyn Hdb>,
    replica: Arc<dyn Replica>,
    /// Имя мастера для отчёта; `None` — «не назван».
    master: Option<String>,
    entries: AtomicUsize,
    stale: AtomicUsize,
}

impl<T: PropagationTarget> ReplicaTarget<T> {
    /// Приём в `inner`, сравнение с `live`, отчёт в `replica`.
    ///
    /// Отказывает, если роль не слейв: мастер, принимающий пуш, — это два мастера, и какой из
    /// них главный, протокол не решает.
    pub fn new(
        inner: T,
        live: Arc<dyn Hdb>,
        replica: Arc<dyn Replica>,
    ) -> Result<ReplicaTarget<T>> {
        let role = replica.role();
        if !role.accepts_propagation() {
            return Err(Error::Hprop(format!(
                "{} does not accept a propagation: only a slave does, and a master receiving one \
                 would make two masters of one realm",
                role.name()
            )));
        }
        Ok(ReplicaTarget {
            inner,
            live,
            replica,
            master: None,
            entries: AtomicUsize::new(0),
            stale: AtomicUsize::new(0),
        })
    }

    /// Имя мастера, которое попадёт в [`SyncState::master`].
    pub fn with_master(mut self, name: impl Into<String>) -> Self {
        self.master = Some(name.into());
        self
    }

    /// Сколько записей применено в этом пуш.
    pub fn applied(&self) -> usize {
        self.entries.load(Ordering::Relaxed)
    }

    /// Сколько записей пропущено как старше текущих.
    pub fn stale(&self) -> usize {
        self.stale.load(Ordering::Relaxed)
    }
}

impl<T: PropagationTarget> PropagationTarget for ReplicaTarget<T> {
    fn store(&self, entry: HdbEntry) -> Result<()> {
        // `fetch` может не знать принципала — это не ошибка: новая запись его и создаёт.
        if let Some(current) = self.live.fetch(&entry.principal)?
            && entry.kvno < current.kvno
        {
            self.stale.fetch_add(1, Ordering::Relaxed);
            // Причина не теряется: она в счётчике и в `SyncState::stale`, а запись в лог —
            // вызывающего, у которого есть и имя принципала, и оба `kvno`.
            return Ok(());
        }
        self.inner.store(entry)?;
        self.entries.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn commit(&self) -> Result<()> {
        self.inner.commit()?;
        self.replica.record(SyncState {
            at: super::now(),
            entries: self.applied(),
            stale: self.stale(),
            master: self.master.clone(),
        });
        Ok(())
    }
}

/// Итог пуша для отчёта: то, что `hpropd` вернул, и то, что слейв об этом помнит.
///
/// Две вещи вместе, потому что порознь они вводят в заблуждение: `Summary` говорит, что пришло,
/// `SyncState` — что из этого стало базой.
#[derive(Debug, Clone)]
pub struct Replicated {
    /// Что принял `hpropd`.
    pub summary: Summary,
    /// Что записала реплика.
    pub sync: Option<SyncState>,
}

impl Replicated {
    /// Собрать отчёт из того, что принял `hpropd`, и того, что помнит реплика.
    pub fn new(summary: Summary, replica: &dyn Replica) -> Replicated {
        Replicated {
            summary,
            sync: replica.last_sync(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Enctype, OwnCipher};
    use crate::hdb::MemoryHdb;

    fn principal(name: &str) -> Principal {
        Principal::parse(&format!("{name}@EXAMPLE.COM")).unwrap()
    }

    fn entry(kvno: u32) -> HdbEntry {
        let mut e = HdbEntry::user(principal("alice"));
        e.add_password_key(&OwnCipher, Enctype::Aes256Sha1, b"pw", kvno)
            .unwrap();
        e
    }

    /// Слейв отказывает в каждой пишущей операции и считает их, а чтение проходит.
    #[test]
    fn a_slave_refuses_every_write_and_counts_it() {
        let live = MemoryHdb::new();
        live.insert(entry(1)).unwrap();
        let replica = Arc::new(Slave::new());
        let read_only = ReadOnly::new(live, Arc::clone(&replica) as Arc<dyn Replica>);

        // Чтение — проходит: слейв обязан отдавать тикеты.
        assert!(read_only.fetch(&principal("alice")).unwrap().is_some());

        assert!(matches!(
            read_only.store(entry(2)),
            Err(Error::Forbidden(_))
        ));
        assert!(matches!(
            read_only.remove(&principal("alice")),
            Err(Error::Forbidden(_))
        ));
        assert!(matches!(
            read_only.rename(&principal("alice"), &principal("bob")),
            Err(Error::Forbidden(_))
        ));
        assert!(matches!(
            read_only.store_policy(Policy {
                name: "default".into(),
                ..Policy::default()
            }),
            Err(Error::Forbidden(_))
        ));
        assert!(matches!(
            read_only.remove_policy("default"),
            Err(Error::Forbidden(_))
        ));

        assert_eq!(
            replica.refused_writes(),
            5,
            "каждая пишущая операция — отдельный отказ, чтобы счётчик отвечал на «сколько раз»"
        );
        // И запись осталась прежней: отказ не оставил половины.
        assert_eq!(
            read_only.fetch(&principal("alice")).unwrap().unwrap().kvno,
            1
        );
    }

    /// Роль решает, разрешена ли запись, а `ReadOnly` — запрещает независимо от роли.
    #[test]
    fn the_role_decides_and_the_wrapper_refuses() {
        assert!(Role::Standalone.accepts_writes());
        assert!(!Role::Slave.accepts_writes());
        assert!(Role::Master.accepts_writes());
        assert!(Role::Slave.accepts_propagation());
        assert!(!Role::Master.accepts_propagation());
        assert!(!Role::Standalone.accepts_propagation());

        for replica in [
            Arc::new(Standalone) as Arc<dyn Replica>,
            Arc::new(Master) as Arc<dyn Replica>,
        ] {
            assert!(replica.writable());
            assert_eq!(replica.refused_writes(), 0);
            // Обёртка отказывает и здесь: её задача — запретить запись, а не рассудить, кто прав.
            let read_only = ReadOnly::new(MemoryHdb::new(), Arc::clone(&replica));
            assert!(read_only.store(entry(1)).is_err());
            assert_eq!(replica.refused_writes(), 0, "мастер отказов не считает");
        }
    }

    /// Пуш на мастера или на одиночный контроллер — отказ: два мастера протокол не различает.
    #[test]
    fn a_propagation_to_a_non_slave_is_refused() {
        for replica in [
            Arc::new(Standalone) as Arc<dyn Replica>,
            Arc::new(Master) as Arc<dyn Replica>,
        ] {
            let err = ReplicaTarget::new(
                crate::hprop::StagedHdb::new(Arc::new(MemoryHdb::new())),
                Arc::new(MemoryHdb::new()),
                replica,
            )
            .unwrap_err();
            let text = err.to_string();
            assert!(
                text.contains("only a slave"),
                "отказ называет правило: {text}"
            );
        }
    }

    /// Запись старше текущей не применяется и попадает в `SyncState::stale`.
    #[test]
    fn an_older_entry_does_not_roll_the_keys_back() {
        let live = Arc::new(MemoryHdb::new());
        live.insert(entry(3)).unwrap();
        let replica = Arc::new(Slave::new());
        let staging: Arc<dyn Hdb> = Arc::new(MemoryHdb::new());
        let target = ReplicaTarget::new(
            crate::hprop::StagedHdb::new(Arc::clone(&staging)),
            Arc::clone(&live) as Arc<dyn Hdb>,
            Arc::clone(&replica) as Arc<dyn Replica>,
        )
        .unwrap();

        target.store(entry(2)).unwrap();
        target.commit().unwrap();

        assert_eq!(target.applied(), 0);
        assert_eq!(target.stale(), 1);
        assert!(
            staging.fetch(&principal("alice")).unwrap().is_none(),
            "старшая запись не должна попасть в базу: клиент с тикетом kvno 3 получил бы \
             BAD_INTEGRITY"
        );
        let sync = replica.last_sync().expect("the push was recorded");
        assert_eq!(sync.entries, 0);
        assert_eq!(sync.stale, 1);
    }

    /// Запись новее и той же версии применяется: восстановление после аварии — это повтор.
    #[test]
    fn a_newer_or_equal_entry_is_applied_and_the_sync_is_recorded() {
        let live = Arc::new(MemoryHdb::new());
        live.insert(entry(3)).unwrap();
        let replica = Arc::new(Slave::new());
        let staging: Arc<dyn Hdb> = Arc::new(MemoryHdb::new());
        let target = ReplicaTarget::new(
            crate::hprop::StagedHdb::new(Arc::clone(&staging)),
            Arc::clone(&live) as Arc<dyn Hdb>,
            Arc::clone(&replica) as Arc<dyn Replica>,
        )
        .unwrap()
        .with_master("kdc1.example.com");

        target.store(entry(3)).unwrap();
        target.store(entry(4)).unwrap();
        target.commit().unwrap();

        assert_eq!(target.applied(), 2);
        let sync = replica.last_sync().expect("recording the push");
        assert_eq!(sync.entries, 2);
        assert_eq!(sync.stale, 0);
        assert_eq!(sync.master.as_deref(), Some("kdc1.example.com"));
        assert!(
            sync.at > 0,
            "момент синхронизации записан: без него мониторинг не отличает свежий слейв от \
             застрявшего"
        );
        assert_eq!(staging.fetch(&principal("alice")).unwrap().unwrap().kvno, 4);
    }

    /// Слейв без принятого пуша отвечает `None`, а не нулями: «не синхронизировался ни разу» и
    /// «синхронизировался только что» — разные факты для мониторинга.
    #[test]
    fn a_slave_that_never_synced_says_so() {
        let replica = Slave::new();
        assert_eq!(replica.last_sync(), None);
        assert_eq!(replica.role(), Role::Slave);
        assert!(!replica.writable());
    }
}
