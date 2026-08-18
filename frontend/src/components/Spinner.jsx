export default function Spinner({ size = 24, className = '' }) {
  return (
    <div
      className={`inline-block border-2 border-accent/30 border-t-accent rounded-full animate-spin ${className}`}
      style={{ width: size, height: size }}
    />
  );
}

export function SpinnerRow({ colSpan }) {
  return (
    <tr>
      <td colSpan={colSpan} className="text-center py-16">
        <Spinner />
      </td>
    </tr>
  );
}
