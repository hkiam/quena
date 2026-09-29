## What & why

<!-- What does this change, and why? Link related issues (e.g. "Fixes #123"). -->

## How it was tested

<!-- Tests added/updated, manual steps, platforms tried. Screenshots for UI changes. -->

## Checklist

- [ ] `cargo test --workspace --exclude quena-app` passes
- [ ] `npm run build --prefix app/ui` passes
- [ ] Large bodies stay streaming/windowed; no blocking work on the UI thread or forwarding path
- [ ] New dependencies (if any) use permissive licenses
