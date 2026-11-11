# Vulnerability Candidate Selection App

## Overview

The application has two screens:

1. **Advisory** — create or edit a vulnerability description and configure the candidate-selection pipeline.
2. **History** — browse all previously added vulnerability descriptions and reopen them.

## Screen 1: Advisory

This screen is used to create or edit a vulnerability description and configure the inputs for candidate selection.

### 1. Vulnerability Details

Display the following fields:

- **CVE** — optional text input.
- **CWE** — input supporting multiple CWE identifiers.
  - When a CVE is entered, automatically populate the associated CWE identifiers.
  - Allow the user to edit the populated CWE values.
- **Title** — auto-resizing text input that adjusts to the entered content.
- **Description** — auto-resizing text area, initially two lines high.
- **Severity** — selectable value: `low`, `medium`, `high`, or `critical`.

Place the CVE and CWE inputs side by side.

### 2. Fix Examples

Allow the user to add multiple vulnerable/fixed code example pairs.

Each pair contains two side-by-side code inputs:

- **Vulnerable code** — the code before the fix.
- **Fixed code** — the corresponding corrected code.

Behavior:

- Place both inputs in the same row.
- Add a draggable vertical divider between them. The user can resize the left input; the right input must automatically occupy the remaining available width.
- When the user starts entering content in the last empty pair, automatically append another empty pair below it.
- Show a delete button for a pair when either of its inputs is focused.

### 3. Evaluation Projects

Provide an input for adding project URLs to the **evaluation project set**.

These projects are used to evaluate vulnerability patterns and measure how many candidate functions they identify.

Allow the user to add multiple project URLs.

### 4. Vulnerable Code Regex Patterns

Provide a section for managing regex patterns that identify potentially vulnerable code.

- Add a **Generate Regexes** button that generates candidate vulnerable-code regex patterns based on the advisory description and fix examples.
- Display the generated patterns as editable inputs.
- Allow the user to add patterns manually.
- When the user starts entering a pattern in the last empty input, automatically append another empty input.
- Provide an evaluation button next to each pattern.
- Clicking the evaluation button runs the pattern against the current evaluation project set and displays the number of candidate functions it identifies.

### 5. Vulnerable AST Regex Patterns

Provide a separate section for regex patterns targeting vulnerable code structures in the AST.

Follow the same interaction model as the vulnerable-code regex section:

- Generate candidate patterns based on the advisory.
- Allow manual editing and adding patterns.
- Automatically append an empty input when the last one is populated.
- Allow individual pattern evaluation against the evaluation project set.
- Display the number of candidate functions identified by each pattern.

### 6. Vulnerable Code Snippets

Provide a section for adding vulnerable code snippets (code slices) used for semantic code search.

- Display snippets as editable inputs.
- Allow the user to add multiple snippets.
- Automatically append an empty input when the last one is populated.

### 7. Apply

Display an **Apply** button at the bottom of the screen.

Clicking it starts the vulnerability candidate-selection pipeline using the current advisory details, fix examples, evaluation projects, regex patterns, AST patterns, and code snippets.

When editing an existing advisory, Apply should run the pipeline using the updated data.

## Screen 2: History

Display all previously added vulnerability descriptions, sorted by creation time in descending order (newest first).

Each item should show:

- **Title** — the vulnerability name.
- **Metadata** — CVE (if available), CWE identifiers, and severity.
- **Creation time** — displayed on the right side of the item.

Clicking an item opens its advisory in the first screen, pre-populates all saved fields, and allows the user to edit the advisory and run the candidate-selection pipeline again.

## General Behavior

- The application must support both creating new advisories and editing existing ones.
- All advisory fields and pattern collections must be preserved when navigating between screens.
- Automatically generated patterns must remain editable.
- Dynamic inputs must always provide an empty row for adding another item.
- Deleting a row must not accidentally delete or modify other rows.
- Editing an advisory must preserve its original creation timestamp.