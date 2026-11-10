use super::pattern_applies;

#[test]
fn matcher_patterns_follow_the_next_forms() {
    assert!(pattern_applies("/api/:path*", "/api/todos"));
    assert!(!pattern_applies("/dashboard/:path*", "/api/todos"));
    assert!(!pattern_applies(
        "/((?!api|_next/static|favicon.ico).*)",
        "/api/todos"
    ));
    assert!(pattern_applies(
        "/((?!_next/static|_next/image|.*\\.png$).*)",
        "/api/todos"
    ));
    assert!(pattern_applies("/api/todos", "/api/todos"));
    assert!(!pattern_applies("/api/other", "/api/todos"));
}
