# TODO

## Open

(none)

## Hardware investigation notes

Based on the evidence gathered so far:

- `portcls` (audio kernel driver) appears in most BSODs — disable audio device power
  management: Device Manager → audio adapter → Power Management → uncheck
  "Allow the computer to turn off this device to save power"
- Also check for Realtek/Intel HD Audio driver updates
- `dxgkrnl` crash (Jun 21) = graphics driver power issue — update GPU driver if not current
- `usbccgp` crash (Jun 24) = USB device stalled on power transition — disconnect USB
  devices before sleep/shutdown as a workaround
