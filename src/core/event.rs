/// イベントバス（将来の実装用スタブ）
///
/// モジュール間のイベント伝達を担当する。
/// 現時点では構造のみ定義し、実装は後続の Issue で行う。
pub struct EventBus;

impl EventBus {
    /// 新しいイベントバスを作成する
    pub fn new() -> Self {
        EventBus
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}
