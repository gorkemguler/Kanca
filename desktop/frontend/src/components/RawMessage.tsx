interface RawMessageProps {
  title: string;
  value: string;
  editable?: boolean;
  onChange?: (v: string) => void;
  placeholder?: string;
}

/** RawMessage renders one side of an HTTP transaction as raw text, either
 *  read-only (a captured response) or editable (a request being crafted). */
export default function RawMessage({
  title,
  value,
  editable,
  onChange,
  placeholder,
}: RawMessageProps) {
  return (
    <div className="msg">
      <div className="msg-head">{title}</div>
      {editable ? (
        <textarea
          spellCheck={false}
          value={value}
          placeholder={placeholder}
          onChange={(e) => onChange?.(e.target.value)}
        />
      ) : (
        <pre>{value || <span className="dim">{placeholder ?? ""}</span>}</pre>
      )}
    </div>
  );
}
