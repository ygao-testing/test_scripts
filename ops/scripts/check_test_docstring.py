import re
import sys

# Regular expression object to capture test function names and their corresponding docstrings, only if a docstring is present.
# This can be used to check formatting only for tests that include docstrings, ignoring tests without docstrings.
# TEST_NAME_DOCSTRING_REGEX = re.compile(r'(def\s+test_\w+.*?)\):\s*"""(.*?)"""', re.DOTALL)

# Regular expression object to capture test function names and their corresponding docstrings, if present;
# if there is no docstring, it matches any whitespace following the function signature
TEST_NAME_DOCSTRING_REGEX = re.compile(r'(def\s+test_\w+.*?)\):\s*(?:"""(.*?)"""|\s*)', re.DOTALL)


def combine_and_trim(lines: list[str]) -> str:
    """Combines lines without adding extra whitespace."""
    return " ".join(line.strip() for line in lines if line.strip())


def parse_sections(docstring: str) -> tuple[str | None, str | None, str | None, str | None, str | None]:
    """
    Splits a docstring into 'Description', 'Given', 'When', 'Then', and 'Args' sections.

    Returns:
        A tuple containing each section's text or None if missing.
    """
    lines = docstring.splitlines()
    description_lines = []
    given, when, then, args = [], [], [], []
    current_section = "description"  # Start by assuming lines are part of the description

    for line in lines:
        line = line.strip()

        # Skip leading empty lines at the start of the docstring
        if current_section == "description" and not line:
            continue

        # Check for section headers and update the current section
        if line.startswith("Given:"):
            current_section = "given"
            given.append(line[len("Given:"):].strip())
        elif line.startswith("When:"):
            current_section = "when"
            when.append(line[len("When:"):].strip())
        elif line.startswith("Then:"):
            current_section = "then"
            then.append(line[len("Then:"):].strip())
        elif line.startswith("Args:"):
            current_section = "args"
            args.append(line[len("Args:"):].strip())
        else:
            # Add lines to the current section
            if current_section == "description":
                description_lines.append(line)
            elif current_section == "given":
                given.append(line)
            elif current_section == "when":
                when.append(line)
            elif current_section == "then":
                then.append(line)
            elif current_section == "args":
                args.append(line)

    # Finalize each section by joining lines
    description_text = combine_and_trim(description_lines)
    given_text = combine_and_trim(given)
    when_text = combine_and_trim(when)
    then_text = combine_and_trim(then)
    args_text = combine_and_trim(args)

    return description_text, given_text, when_text, then_text, args_text


def check_docstring_for_sections(filepath: str) -> bool:
    """
    Checks if test function docstrings in a file have a description, 'Given', 'When', 'Then', and 'Args' sections.

    Returns:
        True if all docstrings follow the format, False if any are missing sections.
    """
    with open(filepath, 'r') as file:
        content = file.read()

    matches = TEST_NAME_DOCSTRING_REGEX.findall(content)
    all_tests_passed = True

    for test_function, docstring in matches:
        test_name = re.match(r'def\s+(\w+)', test_function).group(1)
        # If the test function is missing a docstring, log an error, mark as failed, and skip further checks for this function.
        if not docstring:
            print(f"Error: Test function '{test_name}' in {filepath} is missing a docstring.")
            all_tests_passed = False
            continue

        # Define the minimum length requirements for each section
        REQUIREMENTS = {
            "description": 20,
            "given": 5,
            "when": 20,
            "then": 20,
            "args": 20,
        }
        # Parse all sections from the docstring
        description, given, when, then, args = parse_sections(docstring)
        sections = {"description": description, "given": given, "when": when, "then": then, "args": args}

        # Loop through each section to check presence and length
        for section, content in sections.items():
            min_length = REQUIREMENTS[section]

            # Check if the section is missing
            if not content:
                print(f"Error: Test function '{test_name}' in {filepath} is missing the '{section.capitalize()}' section.")
                all_tests_passed = False

            # Check if the section is present but shorter than the required length
            elif len(content) < min_length:
                print(
                    f"Error: Test function '{test_name}' in {filepath} has a '{section.capitalize()}' section "
                    f"that is shorter than {min_length} characters."
                )
                all_tests_passed = False

    return all_tests_passed


def main():
    """Exits with status 1 if any file has improperly formatted docstrings."""
    files_to_check = sys.argv[1:]
    all_tests_passed = True

    for file in files_to_check:
        if file.endswith(".py") and not check_docstring_for_sections(file):
            all_tests_passed = False

    if not all_tests_passed:
        sys.exit(1)


if __name__ == '__main__':
    main()
