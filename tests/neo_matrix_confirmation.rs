use super::confirm_matrix_on;
use std::io::Cursor;

#[test]
fn activation_requires_an_explicit_y_after_the_crash_warning() {
    for answer in ["Y\n", "y\r\n", " Y \n"] {
        let mut output = Vec::new();
        assert!(confirm_matrix_on(&mut Cursor::new(answer), &mut output).unwrap());
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("can crash running emulators or virtual machines"));
        assert!(text.contains("Close them before continuing."));
        assert!(text.ends_with("Turn MatrixHV ON? [Y/N] (default N): "));
    }
}

#[test]
fn cancellation_and_eof_never_confirm_activation() {
    for answer in ["N\n", "n\r\n", "\n", "", "yes\n", "1\n", "Y N\n"] {
        assert!(!confirm_matrix_on(&mut Cursor::new(answer), &mut Vec::new()).unwrap());
    }
}

#[test]
fn invalid_answers_prompt_again_without_implicitly_confirming() {
    for (answer, confirmed) in [("yes\nY\n", true), ("invalid\nN\n", false)] {
        let mut output = Vec::new();
        assert_eq!(
            confirm_matrix_on(&mut Cursor::new(answer), &mut output).unwrap(),
            confirmed
        );
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("Enter Y or N."));
        assert_eq!(text.matches("Turn MatrixHV ON?").count(), 2);
    }
}
