/**
 * Consistent page-header bar — every page previously rolled its own inline
 * <h1>/<p> pair with slightly different spacing. This is the one place that
 * pattern lives now.
 */
export default function PageHeader({ title, sub, children }) {
  return (
    <div className="flex items-start justify-between gap-4 mb-6">
      <div>
        <h1 className="text-xl font-bold text-ink tracking-tight">{title}</h1>
        {sub && <p className="text-sm text-ink-faint mt-1">{sub}</p>}
      </div>
      {children && <div className="flex items-center gap-2 shrink-0">{children}</div>}
    </div>
  );
}
