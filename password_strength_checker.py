"""
Password Strength Checker (Task ID: task1)
------------------------------------------
A complete Python application to evaluate password strength based on:
1. Minimum Length (>= 8 characters)
2. Uppercase letters (A-Z)
3. Lowercase letters (a-z)
4. Numeric digits (0-9)
5. Special characters (!@#$%^&* etc.)
"""

import string

# Define the set of valid special characters using standard ASCII punctuation
SPECIAL_CHARACTERS = set(string.punctuation)


def evaluate_password(password: str) -> dict:
    """
    Evaluates password strength across 5 criteria.
    Returns a dictionary containing score, percentage, classification, and suggestions.
    """
    # Check for empty or whitespace-only input
    if not password or password.isspace():
        return {
            "score": 0,
            "percentage": 0,
            "classification": "Invalid Input",
            "feedback": ["Password cannot be empty or contain only whitespace."],
            "suggestions": ["Please enter a valid password."]
        }

    score = 0
    feedback = []
    suggestions = []

    # Criterion 1: Minimum Length (8+ characters)
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("❌ Less than 8 characters long.")
        suggestions.append("Make your password at least 8 characters long.")

    # Criterion 2: Uppercase Letters (A-Z)
    if any(char.isupper() for char in password):
        score += 1
    else:
        feedback.append("❌ Missing uppercase letter (A-Z).")
        suggestions.append("Add at least one capital letter.")

    # Criterion 3: Lowercase Letters (a-z)
    if any(char.islower() for char in password):
        score += 1
    else:
        feedback.append("❌ Missing lowercase letter (a-z).")
        suggestions.append("Add at least one small letter.")

    # Criterion 4: Numeric Digits (0-9)
    if any(char.isdigit() for char in password):
        score += 1
    else:
        feedback.append("❌ Missing numeric digit (0-9).")
        suggestions.append("Include at least one number.")

    # Criterion 5: Special Characters (!@#$%^&* etc.)
    if any(char in SPECIAL_CHARACTERS for char in password):
        score += 1
    else:
        feedback.append("❌ Missing special character (!@#$%^&* etc.).")
        suggestions.append("Include at least one special character like @, #, $, %, or !.")

    # Calculate percentage score
    percentage = (score / 5) * 100

    # Categorize password strength rating
    if score <= 1:
        classification = "Weak"
    elif score in (2, 3):
        classification = "Moderate"
    elif score == 4:
        classification = "Strong"
    else:
        classification = "Very Strong"

    return {
        "score": score,
        "percentage": percentage,
        "classification": classification,
        "feedback": feedback,
        "suggestions": suggestions
    }


def print_report(password_display: str, result: dict):
    """Prints a clean formatted security analysis report."""
    print("\n" + "=" * 45)
    print("        PASSWORD STRENGTH ANALYSIS")
    print("=" * 45)
    
    if result["classification"] == "Invalid Input":
        print(f"Status        : {result['classification']}")
        print(f"Error         : {result['feedback'][0]}")
        print("=" * 45 + "\n")
        return

    print(f"Target Input   : {password_display}")
    print(f"Overall Rating : {result['classification']}")
    print(f"Score          : {result['score']} / 5")
    print(f"Strength       : {result['percentage']:.0f}%")
    print("-" * 45)

    if result["feedback"]:
        print("Missing Requirements:")
        for item in result["feedback"]:
            print(f"  {item}")
        print("-" * 45)
        print("Suggestions for Improvement:")
        for tip in result["suggestions"]:
            print(f"  • {tip}")
    else:
        print("🎉 Excellent! Your password meets all standard safety guidelines.")
    
    print("=" * 45 + "\n")


def run_demo_tests():
    """Runs automated test cases covering Weak, Moderate, Strong, and Very Strong passwords."""
    print("\n--- Running Built-in Test Cases ---")
    test_cases = [
        ("12345", "Weak Password"),
        ("password", "Moderate Password"),
        ("SecurePass12", "Strong Password"),
        ("SecureP@ss2026!", "Very Strong Password"),
        ("   ", "Empty/Whitespace Input")
    ]
    
    for pwd, label in test_cases:
        print(f"\n[Test Case: {label}]")
        analysis = evaluate_password(pwd)
        display_val = pwd if pwd.strip() else "<EMPTY>"
        print_report(display_val, analysis)


def main():
    """Main program execution loop with interactive CLI menu."""
    while True:
        print("==========================================")
        print("    PASSWORD STRENGTH CHECKER (Task ID: task1)")
        print("==========================================")
        print("1. Evaluate your own password")
        print("2. Run automated demo test cases")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1, 2, or 3): ").strip()

        if choice == "1":
            user_pwd = input("\nEnter password to evaluate: ")
            analysis = evaluate_password(user_pwd)
            # Mask password display in output report for basic security
            masked_pwd = "*" * len(user_pwd) if user_pwd else "<EMPTY>"
            print_report(masked_pwd, analysis)
        elif choice == "2":
            run_demo_tests()
        elif choice == "3":
            print("\nExiting program. Goodbye!")
            break
        else:
            print("\nInvalid choice! Please enter 1, 2, or 3.\n")


if __name__ == "__main__":
    main()
