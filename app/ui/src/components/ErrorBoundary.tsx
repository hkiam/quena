// Catches render errors so one broken view (hostile or corrupt payload) never
// blanks the whole window. Changing `resetKey` clears the error.
import { Component, type ErrorInfo, type ReactNode } from "react";
import { t } from "../i18n";

type Props = {
  children: ReactNode;
  /** Any change clears a caught error (e.g. session id + tab). */
  resetKey?: unknown;
  /** Custom fallback; default is the inline "This view failed" box with Retry. */
  fallback?: (error: Error, reset: () => void) => ReactNode;
  /** Label for console logging. */
  name?: string;
};

type State = { error: Error | null; key: unknown };

export function errorMessage(e: unknown): string {
  if (e instanceof Error) return e.message || e.name;
  try {
    return typeof e === "string" ? e : JSON.stringify(e) ?? String(e);
  } catch {
    return String(e);
  }
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null, key: this.props.resetKey };

  static getDerivedStateFromError(error: unknown): Partial<State> {
    return { error: error instanceof Error ? error : new Error(errorMessage(error)) };
  }

  static getDerivedStateFromProps(props: Props, state: State): Partial<State> | null {
    // A new reset key (other session / tab) drops the old error.
    if (!Object.is(props.resetKey, state.key)) return { key: props.resetKey, error: null };
    return null;
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error(`[ui] ${this.props.name ?? "view"} failed:`, error, info.componentStack);
  }

  reset = () => this.setState({ error: null });

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    if (this.props.fallback) return this.props.fallback(error, this.reset);
    return (
      <div className="view-error">
        <div>{t("This view failed: {error}", { error: errorMessage(error) })}</div>
        <button onClick={this.reset}>{t("Retry")}</button>
      </div>
    );
  }
}

/** Full-window fallback for the app root. */
export function AppCrash({ error }: { error: Error }) {
  return (
    <div className="app-crash">
      <h3>{t("Something went wrong in the Quena UI.")}</h3>
      <pre>{errorMessage(error)}</pre>
      <p className="muted">{t("Capture keeps running in the background. Reloading the UI does not lose recorded sessions.")}</p>
      <button onClick={() => window.location.reload()}>{t("Reload UI")}</button>
    </div>
  );
}
