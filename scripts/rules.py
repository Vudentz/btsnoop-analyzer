"""
rules.py - JSON rule loader and schema validation.

Loads declarative rule files from the ``rules/`` directory and provides
compiled rule sets for use by detect, annotate, and diagnose steps.
"""

import json
import os
import re
import warnings


# ---------------------------------------------------------------------------
# Rule data classes
# ---------------------------------------------------------------------------

class AbsenceCheck:
    """Detect errors when an expected pattern is absent.

    If ``prerequisite`` matches at least one line but ``expected``
    matches none, this counts as an error with the given ``message``.
    """
    __slots__ = ("prerequisite", "expected", "message")

    def __init__(self, prerequisite, expected, message):
        self.prerequisite = prerequisite
        self.expected = expected
        self.message = message


class MatchCondition:
    """Compiled match condition for a rule."""
    __slots__ = ("field", "contains", "pattern", "all_of",
                 "any_of", "not_contains")

    def __init__(self, field, contains=None, pattern=None,
                 all_of=None, any_of=None, not_contains=None):
        self.field = field
        self.contains = contains
        self.pattern = pattern  # compiled regex
        self.all_of = all_of    # list of substrings
        self.any_of = any_of    # list of substrings
        self.not_contains = not_contains

    def test(self, pkt):
        """Test this condition against a Packet.

        Returns True if the condition matches.
        """
        text = self._get_field(pkt)

        # Positive condition
        matched = False
        if self.contains is not None:
            matched = self.contains in text
        elif self.pattern is not None:
            matched = bool(self.pattern.search(text))
        elif self.all_of is not None:
            matched = all(s in text for s in self.all_of)
        elif self.any_of is not None:
            matched = any(s in text for s in self.any_of)

        if not matched:
            return False

        # Negative guard
        if self.not_contains is not None:
            if self.not_contains in text:
                return False

        return True

    def _get_field(self, pkt):
        """Extract the text field from a packet."""
        if self.field == "summary":
            return pkt.summary
        elif self.field == "body":
            return "\n".join(pkt.body)
        else:  # "full"
            return pkt.summary + "\n" + "\n".join(pkt.body)


class ExtractDef:
    """Compiled extract definition for variable interpolation."""
    __slots__ = ("name", "pattern", "field", "default")

    def __init__(self, name, pattern, field="body", default=""):
        self.name = name
        self.pattern = pattern  # compiled regex
        self.field = field
        self.default = default

    def extract(self, pkt):
        """Extract value from packet, returning default on no match."""
        if self.field == "summary":
            text = pkt.summary
        elif self.field == "body":
            text = "\n".join(pkt.body)
        else:
            text = pkt.summary + "\n" + "\n".join(pkt.body)

        m = self.pattern.search(text)
        if m and m.lastindex:
            return m.group(1)
        return self.default


class MatchRule:
    """A compiled declarative match rule for annotation."""
    __slots__ = ("id", "match", "tags", "priority", "annotation",
                 "extracts", "set_flag", "exclusive", "direction")

    def __init__(self, id=None, match=None, tags=None, priority="key",
                 annotation="", extracts=None, set_flag=None,
                 exclusive=False, direction=None):
        self.id = id
        self.match = match        # MatchCondition
        self.tags = tags or []
        self.priority = priority
        self.annotation = annotation  # template string
        self.extracts = extracts or []  # list of ExtractDef
        self.set_flag = set_flag
        self.exclusive = exclusive
        self.direction = direction  # "<", ">", "@", "=", or None


class DiagnoseAbsence:
    """Flag-based absence check for diagnose step."""
    __slots__ = ("condition_flag", "missing_flag", "message")

    def __init__(self, condition_flag, missing_flag, message):
        self.condition_flag = condition_flag
        self.missing_flag = missing_flag
        self.message = message


class DiagnoseNote:
    """Conditional note for diagnose step with structured condition."""
    __slots__ = ("condition", "message")

    def __init__(self, condition, message):
        self.condition = condition  # dict with counter/flag/op/value
        self.message = message      # template string

    def evaluate(self, annotator):
        """Evaluate the condition against an annotator instance.

        Returns True if the condition is met.
        """
        cond = self.condition
        if "counter" in cond:
            counter_name = cond["counter"]
            value = getattr(annotator, counter_name, 0)
            if not isinstance(value, (int, float)):
                value = 0
            op = cond.get("op", "eq")
            target = cond.get("value", 0)
            ops = {
                "gt": lambda a, b: a > b,
                "gte": lambda a, b: a >= b,
                "eq": lambda a, b: a == b,
                "lt": lambda a, b: a < b,
                "lte": lambda a, b: a <= b,
            }
            return ops.get(op, lambda a, b: False)(value, target)
        elif "flag" in cond:
            flag_name = cond["flag"]
            value = getattr(annotator, flag_name, False)
            target = cond.get("value", True)
            return value == target
        return False

    def format_message(self, annotator):
        """Interpolate {variable} placeholders from annotator attrs."""
        msg = self.message
        # Find all {name} placeholders
        for m in re.finditer(r'\{(\w+)\}', self.message):
            name = m.group(1)
            val = getattr(annotator, name, None)
            if val is None:
                val = getattr(annotator, f"_{name}", "?")
            msg = msg.replace(f"{{{name}}}", str(val))
        return msg


# ---------------------------------------------------------------------------
# RuleSet — compiled rules for one protocol area
# ---------------------------------------------------------------------------

class RuleSet:
    """Compiled rules for a single protocol area."""

    __slots__ = ("name", "focus", "init_filter",
                 "detect_activity", "detect_errors",
                 "detect_absence_checks", "detect_init_filter",
                 "annotate_init_filter", "match_rules",
                 "annotate_hooks", "diagnose_absence_checks",
                 "diagnose_notes", "diagnose_hooks")

    def __init__(self, name, focus):
        self.name = name
        self.focus = focus
        self.init_filter = None           # compiled regex or None
        self.detect_activity = []         # compiled regexes
        self.detect_errors = []           # compiled regexes
        self.detect_absence_checks = []   # AbsenceCheck list
        self.detect_init_filter = None    # compiled regex or None
        self.annotate_init_filter = None  # compiled regex or None
        self.match_rules = []             # MatchRule list
        self.annotate_hooks = []          # hook name strings
        self.diagnose_absence_checks = [] # DiagnoseAbsence list
        self.diagnose_notes = []          # DiagnoseNote list
        self.diagnose_hooks = []          # hook name strings


# ---------------------------------------------------------------------------
# Compilation helpers
# ---------------------------------------------------------------------------

def _compile_patterns(patterns, context):
    """Compile a list of regex pattern strings.

    Args:
        patterns: list of regex strings.
        context: description for error messages.

    Returns:
        list of compiled re.Pattern objects.

    Raises:
        ValueError: if a pattern is invalid.
    """
    compiled = []
    for p in patterns:
        try:
            compiled.append(re.compile(p))
        except re.error as e:
            raise ValueError(
                f"Invalid regex in {context}: {p!r} — {e}") from e
    return compiled


def _compile_init_filter(patterns, context):
    """Compile init_filter patterns into a single alternation regex.

    Returns a compiled regex or None if no patterns.
    """
    if not patterns:
        return None
    compiled = _compile_patterns(patterns, context)
    # Build alternation for efficiency
    alt = "|".join(p.pattern for p in compiled)
    return re.compile(alt)


def _compile_match_condition(raw, rule_id):
    """Compile a match condition from raw JSON dict."""
    field = raw.get("field")
    if not field:
        raise ValueError(
            f"Match condition in rule {rule_id!r} missing 'field'")
    if field not in ("summary", "body", "full"):
        raise ValueError(
            f"Invalid field {field!r} in rule {rule_id!r}")

    contains = raw.get("contains")
    pattern = raw.get("pattern")
    all_of = raw.get("all_of")
    any_of = raw.get("any_of")
    not_contains = raw.get("not_contains")

    # Exactly one positive condition must be present
    positives = sum(1 for x in (contains, pattern, all_of, any_of)
                    if x is not None)
    if positives != 1:
        raise ValueError(
            f"Rule {rule_id!r}: match must have exactly one of "
            f"contains/pattern/all_of/any_of, got {positives}")

    compiled_pattern = None
    if pattern is not None:
        try:
            compiled_pattern = re.compile(pattern)
        except re.error as e:
            raise ValueError(
                f"Invalid regex in rule {rule_id!r}: "
                f"{pattern!r} — {e}") from e

    return MatchCondition(
        field=field,
        contains=contains,
        pattern=compiled_pattern,
        all_of=all_of,
        any_of=any_of,
        not_contains=not_contains,
    )


def _compile_extracts(raw, rule_id):
    """Compile extract definitions from raw JSON dict."""
    if not raw:
        return []
    extracts = []
    for name, spec in raw.items():
        pattern_str = spec.get("pattern")
        if not pattern_str:
            raise ValueError(
                f"Extract {name!r} in rule {rule_id!r} "
                f"missing 'pattern'")
        try:
            compiled = re.compile(pattern_str)
        except re.error as e:
            raise ValueError(
                f"Invalid regex in extract {name!r} of rule "
                f"{rule_id!r}: {pattern_str!r} — {e}") from e
        extracts.append(ExtractDef(
            name=name,
            pattern=compiled,
            field=spec.get("field", "body"),
            default=spec.get("default", ""),
        ))
    return extracts


def _compile_match_rule(raw, index):
    """Compile a single match rule from raw JSON dict."""
    rule_id = raw.get("id", f"rule_{index}")
    match_raw = raw.get("match")
    if not match_raw:
        raise ValueError(
            f"Rule {rule_id!r} missing 'match' condition")
    tags = raw.get("tags")
    if not tags:
        raise ValueError(f"Rule {rule_id!r} missing 'tags'")

    return MatchRule(
        id=rule_id,
        match=_compile_match_condition(match_raw, rule_id),
        tags=tags,
        priority=raw.get("priority", "key"),
        annotation=raw.get("annotation", ""),
        extracts=_compile_extracts(raw.get("extract"), rule_id),
        set_flag=raw.get("set_flag"),
        exclusive=raw.get("exclusive", False),
        direction=raw.get("direction"),
    )


# ---------------------------------------------------------------------------
# Rule file compilation
# ---------------------------------------------------------------------------

def compile_rule_file(data, filename="<unknown>"):
    """Compile a parsed JSON rule file into a RuleSet.

    Args:
        data: parsed JSON dict.
        filename: source filename for error messages.

    Returns:
        RuleSet instance.

    Raises:
        ValueError: on validation errors.
    """
    name = data.get("name")
    focus = data.get("focus")
    if not name:
        raise ValueError(f"{filename}: missing 'name' field")
    if not focus:
        raise ValueError(f"{filename}: missing 'focus' field")

    rs = RuleSet(name, focus)

    # Top-level shared init_filter
    shared_init = data.get("init_filter", [])
    if shared_init:
        rs.init_filter = _compile_init_filter(
            shared_init, f"{filename}:init_filter")

    # --- Detect section ---
    detect = data.get("detect", {})
    if detect:
        rs.detect_activity = _compile_patterns(
            detect.get("activity", []),
            f"{filename}:detect.activity")
        rs.detect_errors = _compile_patterns(
            detect.get("errors", []),
            f"{filename}:detect.errors")

        for i, ac in enumerate(detect.get("absence_checks", [])):
            rs.detect_absence_checks.append(AbsenceCheck(
                prerequisite=ac["prerequisite"],
                expected=ac["expected"],
                message=ac["message"],
            ))

        # Per-step init_filter override
        detect_init = detect.get("init_filter")
        if detect_init:
            rs.detect_init_filter = _compile_init_filter(
                detect_init, f"{filename}:detect.init_filter")

    # --- Annotate section ---
    annotate = data.get("annotate", {})
    if annotate:
        # Per-step init_filter override
        ann_init = annotate.get("init_filter")
        if ann_init:
            rs.annotate_init_filter = _compile_init_filter(
                ann_init, f"{filename}:annotate.init_filter")

        for i, raw_rule in enumerate(
                annotate.get("match_rules", [])):
            rs.match_rules.append(
                _compile_match_rule(raw_rule, i))

        rs.annotate_hooks = annotate.get("hooks", [])

    # --- Diagnose section ---
    diagnose = data.get("diagnose", {})
    if diagnose:
        for ac in diagnose.get("absence_checks", []):
            rs.diagnose_absence_checks.append(DiagnoseAbsence(
                condition_flag=ac["condition_flag"],
                missing_flag=ac["missing_flag"],
                message=ac["message"],
            ))

        for note in diagnose.get("notes", []):
            rs.diagnose_notes.append(DiagnoseNote(
                condition=note["condition"],
                message=note["message"],
            ))

        rs.diagnose_hooks = diagnose.get("hooks", [])

    return rs


def _effective_init_filter(rs, step):
    """Get the effective init_filter for a pipeline step.

    Per-step override takes precedence over the shared top-level
    init_filter.
    """
    if step == "detect":
        return rs.detect_init_filter or rs.init_filter
    elif step == "annotate":
        return rs.annotate_init_filter or rs.init_filter
    return rs.init_filter


# ---------------------------------------------------------------------------
# Rule loading
# ---------------------------------------------------------------------------

_loaded_rules = None  # cached after first load


def load_rules(rules_dir=None):
    """Load and compile all JSON rule files from the rules directory.

    Args:
        rules_dir: Path to rules/ directory.  Defaults to
            ``<repo>/rules/``.

    Returns:
        list of RuleSet instances, sorted by name.

    Raises:
        ValueError: on validation errors (duplicate names, etc.).
    """
    global _loaded_rules
    if _loaded_rules is not None and rules_dir is None:
        return _loaded_rules

    if rules_dir is None:
        # Default: rules/ directory relative to this script's parent
        rules_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "rules")

    if not os.path.isdir(rules_dir):
        return []

    rule_sets = []
    seen_names = {}
    seen_focus = {}

    for fname in sorted(os.listdir(rules_dir)):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(rules_dir, fname)
        with open(fpath, "r") as f:
            data = json.load(f)

        rs = compile_rule_file(data, fname)

        # Uniqueness checks
        if rs.name in seen_names:
            raise ValueError(
                f"Duplicate rule name {rs.name!r} in "
                f"{fname} and {seen_names[rs.name]}")
        if rs.focus in seen_focus:
            raise ValueError(
                f"Duplicate focus {rs.focus!r} in "
                f"{fname} and {seen_focus[rs.focus]}")
        seen_names[rs.name] = fname
        seen_focus[rs.focus] = fname

        rule_sets.append(rs)

    # Flag consistency warning: set_flag referenced in diagnose but
    # never set by any match_rules
    all_set_flags = set()
    for rs in rule_sets:
        for mr in rs.match_rules:
            if mr.set_flag:
                all_set_flags.add(mr.set_flag)

    for rs in rule_sets:
        for da in rs.diagnose_absence_checks:
            for flag_name in (da.condition_flag, da.missing_flag):
                if flag_name not in all_set_flags:
                    warnings.warn(
                        f"Rule {rs.name}: diagnose references flag "
                        f"{flag_name!r} but no match_rule sets it "
                        f"(it may be set by a hook)")

    rule_sets.sort(key=lambda rs: rs.name)

    if rules_dir is None or rules_dir == os.path.join(
            os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), "rules"):
        _loaded_rules = rule_sets

    return rule_sets


def get_rule_set(name_or_focus, rules_dir=None):
    """Look up a RuleSet by name or focus string.

    Returns None if not found.
    """
    for rs in load_rules(rules_dir):
        if rs.name == name_or_focus or rs.focus == name_or_focus:
            return rs
    return None


def clear_cache():
    """Clear the cached rule sets (for testing)."""
    global _loaded_rules
    _loaded_rules = None
