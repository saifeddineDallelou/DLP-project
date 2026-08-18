export default function EmptyState({ icon: Icon, title, sub, action }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 px-6 text-center">
      {Icon && (
        <div className="w-12 h-12 rounded-full bg-white/5 flex items-center justify-center mb-3">
          <Icon size={20} className="text-ink-faint" />
        </div>
      )}
      <p className="text-sm font-medium text-ink-soft">{title}</p>
      {sub && <p className="text-xs text-ink-faint mt-1 max-w-xs">{sub}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
