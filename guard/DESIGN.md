---
name: Quiet Guard
description: A calm operating ledger for verified protection and outstanding review.
colors:
  primary: "#2563eb"
  primary-hover: "#1d4ed8"
  primary-selected: "#edf3ff"
  primary-selected-text: "#2058c7"
  success: "#087f5b"
  success-text: "#08734f"
  success-surface: "#eaf8f1"
  warning: "#986000"
  warning-text: "#885600"
  warning-surface: "#fff4da"
  warning-marker: "#fff5df"
  danger: "#c02d42"
  danger-surface: "#fff0f2"
  canvas: "#f6f8fb"
  surface: "#fff"
  rail: "#fbfcfe"
  text: "#18253b"
  muted: "#52617a"
  border: "#e5eaf1"
  row-divider: "#edf0f5"
  control-border: "#d8e1ee"
  field-border: "#d5dfeb"
  focus: "#8aaffc"
  neutral-state: "#f1f4f8"
typography:
  headline:
    fontFamily: "SUIT, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
    fontSize: "26px"
    fontWeight: 700
    lineHeight: 1.35
    letterSpacing: "-0.025em"
  title:
    fontFamily: "SUIT, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
    fontSize: "16px"
    fontWeight: 680
    letterSpacing: "-0.025em"
  body:
    fontFamily: "SUIT, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
    fontSize: "14px"
  control:
    fontFamily: "SUIT, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
    fontSize: "13px"
    fontWeight: 580
    lineHeight: 1.35
  label:
    fontFamily: "SUIT, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
    fontSize: "12px"
    fontWeight: 550
  detail:
    fontFamily: "SUIT, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
    fontSize: "12px"
    lineHeight: 1.6
  code:
    fontFamily: "Consolas, 'Liberation Mono', monospace"
    fontSize: "12px"
rounded:
  small: "4px"
  badge: "6px"
  field: "7px"
  control: "8px"
  symbol: "9px"
  panel: "12px"
  dialog: "14px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "16px"
  row: "20px"
  panel: "24px"
  workspace: "32px"
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.surface}"
    typography: "{typography.control}"
    rounded: "{rounded.control}"
    padding: "8px 13px"
  button-primary-hover:
    backgroundColor: "{colors.primary-hover}"
  button-secondary:
    backgroundColor: "{colors.surface}"
    textColor: "#2457b1"
    typography: "{typography.control}"
    rounded: "{rounded.control}"
    padding: "8px 13px"
  button-quiet:
    backgroundColor: "transparent"
    textColor: "#34455f"
    typography: "{typography.control}"
    rounded: "{rounded.control}"
    padding: "8px 13px"
  button-danger:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.danger}"
    typography: "{typography.control}"
    rounded: "{rounded.control}"
    padding: "8px 13px"
  field:
    backgroundColor: "{colors.surface}"
    textColor: "#21324c"
    rounded: "{rounded.field}"
    padding: "10px 11px"
  state-warning:
    backgroundColor: "{colors.warning-surface}"
    textColor: "{colors.warning-text}"
    rounded: "{rounded.badge}"
    padding: "5px 8px"
  panel:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.panel}"
  nav-selected:
    backgroundColor: "{colors.primary-selected}"
    textColor: "{colors.primary-selected-text}"
    rounded: "{rounded.control}"
    padding: "11px 13px"
---

# Design System: Quiet Guard

## Overview

**Creative North Star: "The Quiet Operating Ledger"**

Quiet Guard uses restrained blue, white working surfaces and compact Korean labels to make a server's condition readable. Its operating-handover structure presents current condition before outstanding work. Repeated service rows keep service identity, evidence, status and action aligned, while diagnostic detail stays folded until requested.

This is a code-led record of the implemented Operate surface, not a claim of user-approved brand language. The Quiet family commitments are clear Korean labels, restrained blue accents and compact operational screens. The preliminary direction considered a service timetable, audit note, editorial daily brief, emergency contact sheet, operations handover, library ledger and inspection checklist; operations handover was the assigned fifth direction (seed reference: `seed:ef34ddc9d4fa4098`). Its challenger studies contributed evidence separation, stable alignment and a small semantic legend, without adopting their decorative motifs.

**Key Characteristics:**
- Calm, compact rows with exact service names and visible actions.
- Independent protection and risk summaries; evidence determines state.
- Flat white surfaces, light rules and restrained semantic color.
- Self-hosted Korean typography and authored SVG icons.

## Colors

Operating blue anchors actions and selection; neutrals carry most of the screen, and semantic hues identify evidence-backed states.

### Primary
- **Operating Blue:** primary actions, caret, selected navigation family and active working indicator.
- **Deep Action Blue:** primary-button hover feedback.
- **Pale Selected Blue:** selected navigation, active work and preview notice surfaces.

### Secondary
- **Verified Green:** confirmed operation and successful work; paired with a pale green surface.
- **Review Amber:** findings, incomplete checks and waiting states; badge and marker surfaces have separate observed tints.
- **Failure Red:** errors, failed work and protection-off confirmation actions; pale red carries warnings without filling the screen.

### Neutral
- **Cool Canvas:** surrounding workspace and diagnostic background.
- **White Working Surface:** panels, fields, buttons and server header.
- **Rail White:** subtly distinct persistent navigation and search-field background.
- **Ledger Ink / Muted Slate:** primary identity and readable supporting detail.
- **Panel Border / Row Divider:** panel boundaries and repeated record separation.

**The Evidence Color Rule.** Green follows verified evidence or successful work. Unknown, disconnected and stale conditions use neutral or amber state treatments with explicit text.

## Typography

**Display Font:** SUIT Variable with the system sans fallback in the tokens; there is no separate display face.
**Body Font:** the same self-hosted SUIT family, served from `/fonts/suit.woff2`.
**Label/Mono Font:** SUIT for labels and address rows; Consolas with a monospace fallback for commands and diagnostic output.

**Character:** one Korean sans family maintains a precise, quiet reading rhythm. Weight and spacing establish hierarchy without decorative type changes. No synthetic global body line height is implied by the source; paragraphs specify their own leading.

### Hierarchy
- **Headline:** page heading; compact mobile heading (23px).
- **Title:** panel headings; subheadings use a smaller step (15px).
- **Body:** root reading size; service names use this size with stronger weight (640).
- **Control:** desktop button text and supporting page descriptions; many narrow-screen controls use the label step.
- **Label / Detail:** functional labels, states, table data and descriptions; paragraph leading varies by context (1.5–1.75).
- **Code:** command fragments; addresses remain SUIT rather than adopting the provisional document's monospace suggestion.

**The Readable Detail Rule.** Use the label/detail step for compact functional text. Counts, addresses, timestamps and table values use tabular numerals where the source establishes them.

## Layout

The desktop shell uses a fixed side rail (208px), a white server header (80px) and a flexible workspace. Main content is centered with its padding included in the maximum width (1324px); normal desktop inset is the workspace spacing token. This replaces the preliminary document's unimplemented 1260px maximum.

Service rows align symbol, identity, state and action in a four-column grid with row padding vertically and panel padding horizontally. Panels separate with compact gaps (22px). The paired lower overview panels use a slightly wider findings column (1.15:1). The two summary regions separate protection from risk with a thin internal divider. These are observed surface compositions rather than mandatory layouts for every future screen.

At the intermediate breakpoint (1100px), the rail contracts (182px), workspace inset reduces (24px), the lower pair stacks and prerequisite items use two columns. At the narrow breakpoint (760px), navigation becomes a sticky horizontal strip; main inset is (18px), the server header is shorter (68px), summaries stack with a horizontal separator and service actions wrap beneath identity. The prerequisite heading and action stack. Forms and setup steps become single-column.

Exposure data scrolls within its own focusable region. Narrow screens preserve a minimum table width (630px) and show a horizontal-scroll cue. Keep the table's local overflow separate from document overflow. Large screens (1600px and up) add measured vertical breathing room.

## Elevation & Depth

Working panels are flat. Border contrast, pale tonal regions and dividers establish grouping; resting panels and buttons have no decorative shadow. The native confirmation dialog and fixed toast use soft shadows to distinguish temporary foreground feedback.

### Shadow Vocabulary
- **Confirmation:** (`0 15px 70px #15203030`) for the modal dialog; its backdrop is (`#14243f66`).
- **Toast:** (`0 8px 24px #20314b25`) for fixed transient feedback.

**The Working Surface Rule.** Keep working panels flat; reserve the implemented shadow vocabulary for temporary foreground feedback.

## Shapes

Controls use gently rounded corners, larger panels use a softer radius, and dialogs/login panels use the largest observed step. State badges are compact rounded rectangles; tiny circular dots accompany state text. Authored outline SVGs use current text color with a consistent stroke (1.7px), round caps and joins; most interface icons are (18px). Borders are typically (1px). Horizontal table and service dividers are part of the ledger's information structure.

## Components

### Buttons
Compact, quiet actions with explicit Korean labels. Primary buttons use Operating Blue; secondary and quiet variants use white or transparent surfaces with restrained strokes. Danger actions use red text on white. Buttons have a desktop minimum height (36px) and the control radius. Hover changes background and border; disabled controls retain their shape with reduced opacity (0.45). Color and border transitions run (160ms ease). Keyboard focus uses a visible outline (3px) with offset (3px).

### State Badges
Small evidence labels with a colored dot, compact padding and the badge radius. Neutral, success, warning and failure treatments pair text with pale surfaces. State wording remains visible; color does not carry the meaning alone. These are informational badges, not invented filter chips.

### Cards / Containers
White panels with the panel radius, light border and clipped contents. Section headers use compact insets (21px 24px 17px); repeated records align to the same inset. No panel shadow. Inline setup regions use a subtle cool tint and a top rule to remain part of the selected service.

### Inputs / Fields
White fields with a fine border, field radius and readable control-size text. Labels stay above fields. Focus changes the border to Operating Blue and adds an outline (2px) with offset (1px). Search adds an inline SVG and left inset (36px). Checkboxes use the primary accent. Errors appear as explicit text; there is no invented field-error style.

### Navigation
A quiet side rail with outline SVGs, compact labels and pale blue selection. Hover adds a pale neutral surface. Selection is represented by `aria-current="page"`. On narrow screens, the same destinations become a horizontally scrollable top strip; mobile logout remains available in the server header.

### Service Ledger
Three exact services—SSH 접속 보호, 웹 요청 검사 and 노출 점검—use shared aligned rows. Descriptions distinguish enabled configuration from verified behavior. Setup opens inline for the selected service; protection-off actions use a concise confirmation dialog.

### Evidence Table and Work History
Exposure uses local search, tabular values, understated horizontal row borders and a focusable scroll region. Local binding and external connection remain different evidence. Work history uses success/failure/interrupted wording and folded diagnostics; running work uses an indeterminate spinner with elapsed time, without an invented percentage. Reduced-motion preference removes transitions and stops the spinner animation.

## Do's and Don'ts

### Do:
- **Do** use semantic color together with explicit state wording and evidence scope.
- **Do** preserve aligned service rows, compact controls and readable functional detail.
- **Do** use self-hosted SUIT and inline outline SVGs for the working interface.
- **Do** keep wide data locally scrollable and expose its scroll cue on narrow screens.
- **Do** retain visible keyboard focus and respect reduced-motion preferences.

### Don't:
- **Don't** let an unknown, stale or disconnected condition retain a green live indicator.
- **Don't** imply complete protection from enabled software or local binding evidence.
- **Don't** add decorative shadows to the flat working panels.
- **Don't** load third-party fonts or analytics into the management surface.
