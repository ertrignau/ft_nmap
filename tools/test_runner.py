#!/usr/bin/env python3

from pathlib import Path
import re
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = ROOT / "tests"
WIDTH = 78

TEST_HEADER = re.compile(r"^\[test[ \t]+([A-Za-z0-9_-]+)\]$")
NUMBER = re.compile(r"^[0-9]+$")
RANGE = re.compile(r"^([0-9]+)-([0-9]+)$")


# ============================================================================
# Terminal
# ============================================================================

USE_COLOR = sys.stdout.isatty()

RESET   = "\033[0m" if USE_COLOR else ""
BOLD    = "\033[1m" if USE_COLOR else ""
DIM     = "\033[2m" if USE_COLOR else ""

CYAN    = "\033[96m" if USE_COLOR else ""
BLUE    = "\033[94m" if USE_COLOR else ""
MAGENTA = "\033[95m" if USE_COLOR else ""
GREEN   = "\033[92m" if USE_COLOR else ""
RED     = "\033[91m" if USE_COLOR else ""
YELLOW  = "\033[93m" if USE_COLOR else ""
GRAY    = "\033[90m" if USE_COLOR else ""
WHITE   = "\033[97m" if USE_COLOR else ""


def clear_screen():
    if sys.stdout.isatty():
        print("\033[2J\033[H", end="")


def banner(subtitle=None):
    print(CYAN + "=" * WIDTH + RESET)
    print(BOLD + CYAN + "FT_NMAP TEST RUNNER".center(WIDTH) + RESET)

    if subtitle:
        print(
            BLUE
            + subtitle.upper().center(WIDTH)
            + RESET
        )

    print(CYAN + "=" * WIDTH + RESET)


def separator():
    print(GRAY + "-" * WIDTH + RESET)


def error(message):
    print(RED + "Error: " + message + RESET)


def hint(message):
    print(GRAY + message + RESET)


# ============================================================================
# Data
# ============================================================================

class TestError(Exception):
    pass


class Command:
    def __init__(self, kind, text):
        self.kind = kind
        self.text = text


class Test:
    def __init__(self, name):
        self.name = name
        self.description = []
        self.expect = None
        self.ft = None
        self.nmap = None


# ============================================================================
# Test files
# ============================================================================

def available_suites():
    return sorted(
        path.stem
        for path in TESTS_DIR.glob("*.txt")
        if path.is_file()
    )


def load_suite(suite):
    path = TESTS_DIR / (suite + ".txt")

    if not path.is_file():
        raise TestError("unknown test suite: " + suite)

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise TestError("cannot read %s: %s" % (path, exc))

    tests = []
    names = set()
    current = None
    command_seen = False

    for lineno, raw in enumerate(lines, 1):
        text = raw.strip()

        if not text:
            continue

        match = TEST_HEADER.fullmatch(text)

        if match:
            name = match.group(1)

            if name in names:
                raise TestError(
                    "%s:%d: duplicate test '%s'"
                    % (path, lineno, name)
                )

            current = Test(name)
            tests.append(current)
            names.add(name)
            command_seen = False
            continue

        if text.startswith("//"):
            if current is not None and not command_seen:
                comment = text[2:].strip()

                if comment:
                    current.description.append(comment)

            continue

        if current is None:
            raise TestError(
                "%s:%d: content outside a [test ...] block"
                % (path, lineno)
            )

        if text.startswith("expect:"):
            if suite != "parsing":
                raise TestError(
                    "%s:%d: 'expect:' is only allowed in parsing.txt"
                    % (path, lineno)
                )

            if current.expect is not None:
                raise TestError(
                    "%s:%d: duplicate expect"
                    % (path, lineno)
                )

            value = text[len("expect:"):].strip()

            if value not in ("success", "failure"):
                raise TestError(
                    "%s:%d: expect must be 'success' or 'failure'"
                    % (path, lineno)
                )

            current.expect = value
            continue

        if text.startswith("ft:"):
            if current.ft is not None:
                raise TestError(
                    "%s:%d: a test can contain only one ft: command"
                    % (path, lineno)
                )

            command = text[3:].strip()

            if not command:
                raise TestError(
                    "%s:%d: empty ft command"
                    % (path, lineno)
                )

            current.ft = Command("ft", command)
            command_seen = True
            continue

        if text.startswith("nmap:"):
            if suite == "parsing":
                raise TestError(
                    "%s:%d: parsing tests must not contain nmap:"
                    % (path, lineno)
                )

            if current.nmap is not None:
                raise TestError(
                    "%s:%d: a test can contain only one nmap: command"
                    % (path, lineno)
                )

            command = text[5:].strip()

            if not command:
                raise TestError(
                    "%s:%d: empty nmap command"
                    % (path, lineno)
                )

            current.nmap = Command("nmap", command)
            command_seen = True
            continue

        raise TestError(
            "%s:%d: unknown directive: %s"
            % (path, lineno, text)
        )

    if not tests:
        raise TestError("%s: no tests found" % path)

    for test in tests:
        if test.ft is None:
            raise TestError(
                "%s: test '%s' has no ft: command"
                % (path, test.name)
            )

        if suite == "parsing" and test.expect is None:
            raise TestError(
                "%s: parsing test '%s' has no expect:"
                % (path, test.name)
            )

    return tests


# ============================================================================
# Selection
# ============================================================================

def add_number(selected, seen, number, count):
    if number < 1 or number > count:
        raise TestError(
            "test %d does not exist (1-%d)"
            % (number, count)
        )

    index = number - 1

    if index not in seen:
        selected.append(index)
        seen.add(index)


def parse_selection(text, count):
    words = text.split()

    if not words:
        return []

    if words == ["all"]:
        return list(range(count))

    if "all" in words:
        raise TestError(
            "'all' cannot be combined with another selection"
        )

    selected = []
    seen = set()

    for word in words:
        if NUMBER.fullmatch(word):
            add_number(
                selected,
                seen,
                int(word),
                count,
            )
            continue

        match = RANGE.fullmatch(word)

        if match:
            start = int(match.group(1))
            end = int(match.group(2))

            if start > end:
                raise TestError("invalid range: " + word)

            for number in range(start, end + 1):
                add_number(
                    selected,
                    seen,
                    number,
                    count,
                )

            continue

        raise TestError("invalid selection: " + repr(word))

    return selected


# ============================================================================
# Menus
# ============================================================================

def show_suite_menu(suites):
    clear_screen()
    banner()

    print()

    for index, name in enumerate(suites, 1):
        print(
            "  "
            + CYAN
            + ("%2d" % index)
            + RESET
            + "  "
            + name
        )

    print()
    print("  " + GRAY + "q" + RESET + "   quit")
    print()


def show_test_menu(suite, tests):
    clear_screen()
    banner(suite + " tests")

    print()

    for index, test in enumerate(tests, 1):
        print(
            "  "
            + CYAN
            + ("%2d" % index)
            + RESET
            + "  "
            + test.name
        )

    print()
    print(
        GRAY
        + "  all"
        + RESET
        + "   all tests    "
        + GRAY
        + "b"
        + RESET
        + "   back    "
        + GRAY
        + "q"
        + RESET
        + "   quit"
    )
    print()


def invalid_selection(message):
    print()
    error(message)
    hint("Valid: 3   2-5   1 3 6-8   all   b   q")
    print()


# ============================================================================
# Execution
# ============================================================================

def print_description(test):
    print(
        GRAY
        + "[ "
        + test.name
        + " ]"
        + RESET
    )

    for text in test.description:
        print(GRAY + text + RESET)

    if test.expect is not None:
        print(
            GRAY
            + "[ expected: "
            + test.expect
            + " ]"
            + RESET
        )


def command_header(command):
    print()

    if command.kind == "ft":
        print(BOLD + CYAN + "FT_NMAP" + RESET)
        command_color = CYAN
    else:
        print(BOLD + MAGENTA + "NMAP REFERENCE" + RESET)
        command_color = MAGENTA

    print(BOLD + command_color + "$ " + command.text + RESET)
    print(GRAY + "output:" + RESET)


def execute(command):
    command_header(command)

    sys.stdout.flush()

    completed = subprocess.run(
        command.text,
        shell=True,
        executable="/bin/sh",
        cwd=str(ROOT),
    )

    return completed.returncode


def parsing_result(test, returncode):
    if test.expect == "success":
        passed = returncode == 0
    else:
        passed = returncode != 0

    print()

    if passed:
        if test.expect == "success":
            detail = "accepted as expected"
        else:
            detail = "rejected as expected"

        print(
            BOLD
            + GREEN
            + "PASS"
            + RESET
            + GREEN
            + " - "
            + detail
            + RESET
        )
    else:
        if test.expect == "success":
            detail = "unexpected rejection (exit %d)" % returncode
        else:
            detail = "unexpected acceptance"

        print(
            BOLD
            + RED
            + "FAIL"
            + RESET
            + RED
            + " - "
            + detail
            + RESET
        )


def run_test(suite, index, total, test):
    clear_screen()
    banner(
        "%s - test %d/%d"
        % (suite, index, total)
    )

    print()
    print_description(test)

    ft_status = execute(test.ft)

    if suite == "parsing":
        parsing_result(test, ft_status)
    else:
        print()
        print(
            GRAY
            + "ft_nmap exit: %d"
            % ft_status
            + RESET
        )

        if test.nmap is not None:
            nmap_status = execute(test.nmap)

            print()
            print(
                GRAY
                + "nmap exit: %d"
                % nmap_status
                + RESET
            )


def wait_after_test(last):
    if last:
        message = "[Enter] return to menu"
    else:
        message = "[Enter] next test"

    quit_text = "[q] quit"

    if sys.stdout.isatty():
        columns, rows = shutil.get_terminal_size(fallback=(80, 24))

        left = message
        right = quit_text

        gap = columns - len(left) - len(right)

        if gap < 4:
            prompt = left + "  " + right
        else:
            prompt = left + (" " * gap) + right

        # Move to the last terminal row and erase anything already there.
        print(
            "\033[%d;1H\033[2K" % rows
            + GRAY
            + left
            + RESET,
            end="",
        )

        if gap >= 4:
            print(
                (" " * gap)
                + RED
                + right
                + RESET,
                end="",
            )
        else:
            print(
                "  "
                + RED
                + right
                + RESET,
                end="",
            )

        print("\033[?25h", end="", flush=True)
    else:
        print(message + "  " + quit_text, end="", flush=True)

    try:
        value = input(" ")
    except EOFError:
        return False

    return value.strip().lower() not in (
        "q",
        "quit",
        "exit",
    )


def run_selected_interactive(suite, tests, selected):
    for position, index in enumerate(selected):
        run_test(
            suite,
            index + 1,
            len(tests),
            tests[index],
        )

        last = position == len(selected) - 1

        if not wait_after_test(last):
            return

    clear_screen()


# ============================================================================
# Interactive mode
# ============================================================================

def interactive():
    while True:
        suites = available_suites()

        if not suites:
            clear_screen()
            banner()
            print()
            error("no .txt test files found in tests/")
            return 1

        show_suite_menu(suites)

        while True:
            try:
                choice = input("Select suite: ").strip()
            except EOFError:
                print()
                return 0

            if choice in ("q", "quit", "exit"):
                return 0

            if not NUMBER.fullmatch(choice):
                invalid_selection("invalid suite")
                continue

            number = int(choice)

            if number < 1 or number > len(suites):
                invalid_selection("suite does not exist")
                continue

            suite = suites[number - 1]
            break

        try:
            tests = load_suite(suite)
        except TestError as exc:
            error(str(exc))
            input("\nPress Enter...")
            continue

        while True:
            show_test_menu(suite, tests)

            while True:
                try:
                    choice = input("Select tests: ").strip()
                except EOFError:
                    print()
                    return 0

                if choice in ("q", "quit", "exit"):
                    return 0

                if choice in ("b", "back"):
                    break

                try:
                    selected = parse_selection(
                        choice,
                        len(tests),
                    )
                except TestError as exc:
                    invalid_selection(str(exc))
                    continue

                if not selected:
                    invalid_selection("empty selection")
                    continue

                run_selected_interactive(
                    suite,
                    tests,
                    selected,
                )
                break

            if choice in ("b", "back"):
                break


# ============================================================================
# Direct mode
# ============================================================================

def direct(args):
    suite = args[0]

    try:
        tests = load_suite(suite)
    except TestError as exc:
        print(
            "test_runner.py: %s" % exc,
            file=sys.stderr,
        )
        return 1

    if len(args) == 1:
        show_test_menu(suite, tests)
        return 0

    try:
        selected = parse_selection(
            " ".join(args[1:]),
            len(tests),
        )
    except TestError as exc:
        print(
            "test_runner.py: %s" % exc,
            file=sys.stderr,
        )
        return 1

    for index in selected:
        run_test(
            suite,
            index + 1,
            len(tests),
            tests[index],
        )

    return 0


def main():
    if len(sys.argv) == 1:
        return interactive()

    return direct(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())

