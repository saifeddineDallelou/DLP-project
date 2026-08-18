export default function Toggle({ checked, onChange, label }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      onClick={() => onChange(!checked)}
      className={`relative w-10 h-[22px] rounded-full transition-colors duration-150 shrink-0 ${
        checked ? 'bg-accent' : 'bg-surface-elevated border border-border-strong'
      }`}
    >
      <span
        className={`absolute top-0.5 w-[18px] h-[18px] rounded-full shadow transition-transform duration-150 ${
          checked ? 'translate-x-[19px] bg-[#04191b]' : 'translate-x-0.5 bg-ink-faint'
        }`}
      />
    </button>
  );
}
