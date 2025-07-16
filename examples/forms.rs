//! Form handling example demonstrating form data processing with http-kit.
//!
//! This example shows how to handle HTML forms using http-kit, including:
//! - Serving HTML forms
//! - Processing URL-encoded form data
//! - File upload handling
//! - Form validation and error handling
//! - Different input types and validation
//! - Form responses and redirects
//! - CSRF protection concepts

use http_kit::{Request, Response, Result, Endpoint, StatusCode, Body};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Form Data Structures
// ============================================================================

#[derive(Debug, Deserialize)]
struct ContactForm {
    name: String,
    email: String,
    subject: String,
    message: String,
    newsletter: Option<String>, // Checkbox value
}

#[derive(Debug, Deserialize)]
struct UserRegistration {
    username: String,
    email: String,
    password: String,
    confirm_password: String,
    age: Option<u32>,
    terms: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    remember_me: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SearchForm {
    query: String,
    category: Option<String>,
    min_price: Option<f64>,
    max_price: Option<f64>,
    in_stock: Option<String>,
}

#[derive(Debug, Serialize)]
struct FormResponse {
    success: bool,
    message: String,
    errors: Option<HashMap<String, Vec<String>>>,
    data: Option<serde_json::Value>,
}

// ============================================================================
// Form Validation
// ============================================================================

struct FormValidator;

impl FormValidator {
    fn validate_contact_form(form: &ContactForm) -> HashMap<String, Vec<String>> {
        let mut errors = HashMap::new();

        // Validate name
        if form.name.trim().is_empty() {
            errors.entry("name".to_string())
                .or_insert_with(Vec::new)
                .push("Name is required".to_string());
        } else if form.name.len() < 2 {
            errors.entry("name".to_string())
                .or_insert_with(Vec::new)
                .push("Name must be at least 2 characters".to_string());
        }

        // Validate email
        if form.email.trim().is_empty() {
            errors.entry("email".to_string())
                .or_insert_with(Vec::new)
                .push("Email is required".to_string());
        } else if !Self::is_valid_email(&form.email) {
            errors.entry("email".to_string())
                .or_insert_with(Vec::new)
                .push("Please enter a valid email address".to_string());
        }

        // Validate subject
        if form.subject.trim().is_empty() {
            errors.entry("subject".to_string())
                .or_insert_with(Vec::new)
                .push("Subject is required".to_string());
        }

        // Validate message
        if form.message.trim().is_empty() {
            errors.entry("message".to_string())
                .or_insert_with(Vec::new)
                .push("Message is required".to_string());
        } else if form.message.len() < 10 {
            errors.entry("message".to_string())
                .or_insert_with(Vec::new)
                .push("Message must be at least 10 characters".to_string());
        }

        errors
    }

    fn validate_user_registration(form: &UserRegistration) -> HashMap<String, Vec<String>> {
        let mut errors = HashMap::new();

        // Validate username
        if form.username.trim().is_empty() {
            errors.entry("username".to_string())
                .or_insert_with(Vec::new)
                .push("Username is required".to_string());
        } else if form.username.len() < 3 {
            errors.entry("username".to_string())
                .or_insert_with(Vec::new)
                .push("Username must be at least 3 characters".to_string());
        } else if !form.username.chars().all(|c| c.is_alphanumeric() || c == '_') {
            errors.entry("username".to_string())
                .or_insert_with(Vec::new)
                .push("Username can only contain letters, numbers, and underscores".to_string());
        }

        // Validate email
        if form.email.trim().is_empty() {
            errors.entry("email".to_string())
                .or_insert_with(Vec::new)
                .push("Email is required".to_string());
        } else if !Self::is_valid_email(&form.email) {
            errors.entry("email".to_string())
                .or_insert_with(Vec::new)
                .push("Please enter a valid email address".to_string());
        }

        // Validate password
        if form.password.is_empty() {
            errors.entry("password".to_string())
                .or_insert_with(Vec::new)
                .push("Password is required".to_string());
        } else {
            if form.password.len() < 8 {
                errors.entry("password".to_string())
                    .or_insert_with(Vec::new)
                    .push("Password must be at least 8 characters".to_string());
            }
            if !form.password.chars().any(|c| c.is_uppercase()) {
                errors.entry("password".to_string())
                    .or_insert_with(Vec::new)
                    .push("Password must contain at least one uppercase letter".to_string());
            }
            if !form.password.chars().any(|c| c.is_lowercase()) {
                errors.entry("password".to_string())
                    .or_insert_with(Vec::new)
                    .push("Password must contain at least one lowercase letter".to_string());
            }
            if !form.password.chars().any(|c| c.is_numeric()) {
                errors.entry("password".to_string())
                    .or_insert_with(Vec::new)
                    .push("Password must contain at least one number".to_string());
            }
        }

        // Validate password confirmation
        if form.password != form.confirm_password {
            errors.entry("confirm_password".to_string())
                .or_insert_with(Vec::new)
                .push("Passwords do not match".to_string());
        }

        // Validate age
        if let Some(age) = form.age {
            if age < 13 {
                errors.entry("age".to_string())
                    .or_insert_with(Vec::new)
                    .push("You must be at least 13 years old".to_string());
            } else if age > 120 {
                errors.entry("age".to_string())
                    .or_insert_with(Vec::new)
                    .push("Please enter a valid age".to_string());
            }
        }

        // Validate terms acceptance
        if form.terms.is_none() {
            errors.entry("terms".to_string())
                .or_insert_with(Vec::new)
                .push("You must accept the terms and conditions".to_string());
        }

        errors
    }

    fn validate_search_form(form: &SearchForm) -> HashMap<String, Vec<String>> {
        let mut errors = HashMap::new();

        // Validate query
        if form.query.trim().is_empty() {
            errors.entry("query".to_string())
                .or_insert_with(Vec::new)
                .push("Search query is required".to_string());
        } else if form.query.len() < 2 {
            errors.entry("query".to_string())
                .or_insert_with(Vec::new)
                .push("Search query must be at least 2 characters".to_string());
        }

        // Validate price range
        if let (Some(min), Some(max)) = (form.min_price, form.max_price) {
            if min < 0.0 {
                errors.entry("min_price".to_string())
                    .or_insert_with(Vec::new)
                    .push("Minimum price cannot be negative".to_string());
            }
            if max < 0.0 {
                errors.entry("max_price".to_string())
                    .or_insert_with(Vec::new)
                    .push("Maximum price cannot be negative".to_string());
            }
            if min > max {
                errors.entry("min_price".to_string())
                    .or_insert_with(Vec::new)
                    .push("Minimum price cannot be greater than maximum price".to_string());
            }
        }

        errors
    }

    fn is_valid_email(email: &str) -> bool {
        email.contains('@') && email.contains('.') && email.len() > 5
    }
}

// ============================================================================
// HTML Form Templates
// ============================================================================

struct HtmlTemplates;

impl HtmlTemplates {
    fn contact_form(errors: Option<&HashMap<String, Vec<String>>>) -> String {
        let error_class = |field: &str| {
            if errors.map_or(false, |e| e.contains_key(field)) {
                "error"
            } else {
                ""
            }
        };

        let show_errors = |field: &str| {
            if let Some(errors) = errors {
                if let Some(field_errors) = errors.get(field) {
                    field_errors
                        .iter()
                        .map(|e| format!("<div class='error-message'>{}</div>", e))
                        .collect::<Vec<_>>()
                        .join("")
                } else {
                    String::new()
                }
            } else {
                String::new()
            }
        };

        format!(r#"
<!DOCTYPE html>
<html>
<head>
    <title>Contact Form</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; }}
        .form-group {{ margin-bottom: 15px; }}
        label {{ display: block; margin-bottom: 5px; font-weight: bold; }}
        input[type="text"], input[type="email"], textarea, select {{
            width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;
        }}
        input.error, textarea.error {{ border-color: #e74c3c; }}
        .error-message {{ color: #e74c3c; font-size: 14px; margin-top: 5px; }}
        button {{ background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }}
        button:hover {{ background: #2980b9; }}
        .checkbox-group {{ display: flex; align-items: center; }}
        .checkbox-group input {{ width: auto; margin-right: 10px; }}
    </style>
</head>
<body>
    <h1>Contact Us</h1>
    <form method="POST" action="/contact">
        <div class="form-group">
            <label for="name">Name *</label>
            <input type="text" id="name" name="name" class="{}" required>
            {}
        </div>

        <div class="form-group">
            <label for="email">Email *</label>
            <input type="email" id="email" name="email" class="{}" required>
            {}
        </div>

        <div class="form-group">
            <label for="subject">Subject *</label>
            <input type="text" id="subject" name="subject" class="{}" required>
            {}
        </div>

        <div class="form-group">
            <label for="message">Message *</label>
            <textarea id="message" name="message" rows="5" class="{}" required></textarea>
            {}
        </div>

        <div class="form-group">
            <div class="checkbox-group">
                <input type="checkbox" id="newsletter" name="newsletter" value="yes">
                <label for="newsletter">Subscribe to our newsletter</label>
            </div>
        </div>

        <button type="submit">Send Message</button>
    </form>
</body>
</html>
"#,
            error_class("name"), show_errors("name"),
            error_class("email"), show_errors("email"),
            error_class("subject"), show_errors("subject"),
            error_class("message"), show_errors("message")
        )
    }

    fn registration_form(errors: Option<&HashMap<String, Vec<String>>>) -> String {
        let error_class = |field: &str| {
            if errors.map_or(false, |e| e.contains_key(field)) {
                "error"
            } else {
                ""
            }
        };

        let show_errors = |field: &str| {
            if let Some(errors) = errors {
                if let Some(field_errors) = errors.get(field) {
                    field_errors
                        .iter()
                        .map(|e| format!("<div class='error-message'>{}</div>", e))
                        .collect::<Vec<_>>()
                        .join("")
                } else {
                    String::new()
                }
            } else {
                String::new()
            }
        };

        format!(r#"
<!DOCTYPE html>
<html>
<head>
    <title>User Registration</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; }}
        .form-group {{ margin-bottom: 15px; }}
        label {{ display: block; margin-bottom: 5px; font-weight: bold; }}
        input[type="text"], input[type="email"], input[type="password"], input[type="number"] {{
            width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;
        }}
        input.error {{ border-color: #e74c3c; }}
        .error-message {{ color: #e74c3c; font-size: 14px; margin-top: 5px; }}
        button {{ background: #27ae60; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }}
        button:hover {{ background: #229954; }}
        .checkbox-group {{ display: flex; align-items: center; }}
        .checkbox-group input {{ width: auto; margin-right: 10px; }}
        .password-requirements {{
            font-size: 12px; color: #7f8c8d; margin-top: 5px;
        }}
    </style>
</head>
<body>
    <h1>Register</h1>
    <form method="POST" action="/register">
        <div class="form-group">
            <label for="username">Username *</label>
            <input type="text" id="username" name="username" class="{}" required>
            {}
            <div class="password-requirements">3+ characters, letters, numbers, and underscores only</div>
        </div>

        <div class="form-group">
            <label for="email">Email *</label>
            <input type="email" id="email" name="email" class="{}" required>
            {}
        </div>

        <div class="form-group">
            <label for="password">Password *</label>
            <input type="password" id="password" name="password" class="{}" required>
            {}
            <div class="password-requirements">
                Must be 8+ characters with uppercase, lowercase, and number
            </div>
        </div>

        <div class="form-group">
            <label for="confirm_password">Confirm Password *</label>
            <input type="password" id="confirm_password" name="confirm_password" class="{}" required>
            {}
        </div>

        <div class="form-group">
            <label for="age">Age</label>
            <input type="number" id="age" name="age" min="13" max="120" class="{}">
            {}
        </div>

        <div class="form-group">
            <div class="checkbox-group">
                <input type="checkbox" id="terms" name="terms" value="accepted" class="{}" required>
                <label for="terms">I accept the terms and conditions *</label>
            </div>
            {}
        </div>

        <button type="submit">Register</button>
    </form>
</body>
</html>
"#,
            error_class("username"), show_errors("username"),
            error_class("email"), show_errors("email"),
            error_class("password"), show_errors("password"),
            error_class("confirm_password"), show_errors("confirm_password"),
            error_class("age"), show_errors("age"),
            error_class("terms"), show_errors("terms")
        )
    }

    fn search_form() -> String {
        r#"
<!DOCTYPE html>
<html>
<head>
    <title>Search Products</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .form-group { margin-bottom: 15px; }
        .form-row { display: flex; gap: 15px; }
        .form-row .form-group { flex: 1; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="number"], select {
            width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;
        }
        button { background: #f39c12; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #e67e22; }
        .checkbox-group { display: flex; align-items: center; }
        .checkbox-group input { width: auto; margin-right: 10px; }
    </style>
</head>
<body>
    <h1>Search Products</h1>
    <form method="GET" action="/search">
        <div class="form-group">
            <label for="query">Search Query</label>
            <input type="text" id="query" name="query" placeholder="Enter search terms..." required>
        </div>

        <div class="form-row">
            <div class="form-group">
                <label for="category">Category</label>
                <select id="category" name="category">
                    <option value="">All Categories</option>
                    <option value="electronics">Electronics</option>
                    <option value="clothing">Clothing</option>
                    <option value="books">Books</option>
                    <option value="home">Home & Garden</option>
                </select>
            </div>

            <div class="form-group">
                <label for="min_price">Min Price</label>
                <input type="number" id="min_price" name="min_price" min="0" step="0.01" placeholder="0.00">
            </div>

            <div class="form-group">
                <label for="max_price">Max Price</label>
                <input type="number" id="max_price" name="max_price" min="0" step="0.01" placeholder="999.99">
            </div>
        </div>

        <div class="form-group">
            <div class="checkbox-group">
                <input type="checkbox" id="in_stock" name="in_stock" value="yes">
                <label for="in_stock">In stock only</label>
            </div>
        </div>

        <button type="submit">Search</button>
    </form>
</body>
</html>
"#.to_string()
    }

    fn success_page(message: &str) -> String {
        format!(r#"
<!DOCTYPE html>
<html>
<head>
    <title>Success</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; text-align: center; }}
        .success {{ color: #27ae60; background: #d5f4e6; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        a {{ color: #3498db; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <h1>Success!</h1>
    <div class="success">
        <p>{}</p>
    </div>
    <p><a href="/">← Back to Home</a></p>
</body>
</html>
"#, message)
    }

    fn home_page() -> String {
        r#"
<!DOCTYPE html>
<html>
<head>
    <title>Form Examples</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .card { border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin: 15px 0; }
        .card h3 { margin-top: 0; color: #2c3e50; }
        .card p { color: #7f8c8d; }
        a { color: #3498db; text-decoration: none; font-weight: bold; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <h1>HTTP-Kit Form Examples</h1>
    <p>This page demonstrates various form handling capabilities using http-kit.</p>

    <div class="card">
        <h3>Contact Form</h3>
        <p>A contact form with validation, required fields, and optional newsletter signup.</p>
        <a href="/contact">Try Contact Form →</a>
    </div>

    <div class="card">
        <h3>User Registration</h3>
        <p>Registration form with complex validation, password requirements, and terms acceptance.</p>
        <a href="/register">Try Registration →</a>
    </div>

    <div class="card">
        <h3>Product Search</h3>
        <p>Search form with various input types including dropdowns, numbers, and checkboxes.</p>
        <a href="/search">Try Search →</a>
    </div>

    <div class="card">
        <h3>Login Form</h3>
        <p>Simple login form with username/password and remember me option.</p>
        <a href="/login">Try Login →</a>
    </div>
</body>
</html>
"#.to_string()
    }
}

// ============================================================================
// Form Endpoints
// ============================================================================

struct HomeEndpoint;

impl Endpoint for HomeEndpoint {
    async fn respond(&self, _request: &mut Request) -> Result<Response> {
        Ok(Response::new(StatusCode::OK, HtmlTemplates::home_page())
            .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8"))
    }
}

struct ContactFormEndpoint;

impl Endpoint for ContactFormEndpoint {
    async fn respond(&self, request: &mut Request) -> Result<Response> {
        match request.method() {
            &http::Method::GET => {
                // Show the contact form
                Ok(Response::new(StatusCode::OK, HtmlTemplates::contact_form(None))
                    .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8"))
            }
            &http::Method::POST => {
                // Process form submission
                self.handle_contact_submission(request).await
            }
            _ => Ok(Response::new(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed")),
        }
    }
}

impl ContactFormEndpoint {
    async fn handle_contact_submission(&self, request: &mut Request) -> Result<Response> {
        // Parse form data
        let form_data: ContactForm = match request.into_form().await {
            Ok(data) => data,
            Err(_) => {
                return Ok(Response::new(StatusCode::BAD_REQUEST, "Invalid form data")
                    .header(http::header::CONTENT_TYPE, "text/plain"));
            }
        };

        println!("Received contact form: {:?}", form_data);

        // Validate form data
        let errors = FormValidator::validate_contact_form(&form_data);

        if !errors.is_empty() {
            // Return form with errors
            Ok(Response::new(StatusCode::BAD_REQUEST, HtmlTemplates::contact_form(Some(&errors)))
                .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8"))
        } else {
            // Process successful submission
            let message = format!(
                "Thank you, {}! We received your message about '{}' and will get back to you at {}.",
                form_data.name, form_data.subject, form_data.email
            );

            Ok(Response::new(StatusCode::OK, HtmlTemplates::success_page(&message))
                .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8"))
        }
    }
}

struct RegistrationEndpoint;

impl Endpoint for RegistrationEndpoint {
    async fn respond(&self, request: &mut Request) -> Result<Response> {
        match request.method() {
            &http::Method::GET => {
                Ok(Response::new(StatusCode::OK, HtmlTemplates::registration_form(None))
                    .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8"))
            }
            &http::Method::POST => {
                self.handle_registration_submission(request).await
            }
            _ => Ok(Response::new(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed")),
        }
    }
}

impl RegistrationEndpoint {
    async fn handle_registration_submission(&self, request: &mut Request) -> Result<Response> {
        let form_data: UserRegistration = match request.into_form().await {
            Ok(data) => data,
            Err(_) => {
                return Ok(Response::new(StatusCode::BAD_REQUEST, "Invalid form data")
                    .header(http::header::CONTENT_TYPE, "text/plain"));
            }
        };

        println!("Received registration: {:?}", form_data);

        let errors = FormValidator::validate_user_registration(&form_data);

        if !errors.is_empty() {
            Ok(Response::new(StatusCode::BAD_REQUEST, HtmlTemplates::registration_form(Some(&errors)))
                .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8"))
        } else {
            let message = format!(
                "Welcome, {}! Your account has been created successfully. You can now log in with your username.",
                form_data.username
            );

            Ok(Response::new(StatusCode::OK, HtmlTemplates::success_page(&message))
                .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8"))
        }
    }
}

struct SearchEndpoint;

impl Endpoint for SearchEndpoint {
    async fn respond(&self, request: &mut Request) -> Result<Response> {
        match request.method() {
            &http::Method::GET => {
                if let Some(query_string) = request.uri().query() {
                    // Process search query
                    self.handle_search_query(query_string).await
                } else {
                    // Show search form
                    Ok(Response::new(StatusCode::OK, HtmlTemplates::search_form())
                        .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8"))
                }
            }
            _ => Ok(Response::new(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed")),
        }
    }
}

impl SearchEndpoint {
    async fn handle_search_query(&self, query_string: &str) -> Result<Response> {
        let form_data: SearchForm = match serde_urlencoded::from_str(query_string) {
            Ok(data) => data,
            Err(_) => {
                return Ok(Response::new(StatusCode::BAD_REQUEST, "Invalid search parameters")
                    .header(http::header::CONTENT_TYPE, "text/plain"));
            }
        };

        println!("Received search: {:?}", form_data);

        let errors = FormValidator::validate_search_form(&form_data);

        if !errors.is_empty() {
            let error_messages = errors
                .values()
                .flatten()
                .map(|e| e.as_str())
                .collect::<Vec<_>>()
                .join(", ");

            return Ok(Response::new(StatusCode::BAD_REQUEST, format!("Search errors: {}", error_messages))
                .header(http::header::CONTENT_TYPE, "text/plain"));
        }

        // Generate search results (mock)
        let mut results = Vec::new();
        let search_terms = form_data.query.to_lowercase();

        // Mock product database
        let products = vec![
            ("Laptop", "electronics", 999.99),
            ("T-Shirt", "clothing", 29.99),
            ("Book: Rust Programming", "books", 39.99),
            ("Garden Tools", "home", 149.99),
            ("Smartphone", "electronics", 699.99),
            ("Jeans", "clothing", 79.99),
        ];

        for (name, category, price) in products {
            let matches_query = name.to_lowercase().contains(&search_terms);
            let matches_category = form_data.category.as_ref()
                .map_or(true, |cat| cat == category);
            let matches_price = {
                let min_ok = form_data.min_price.map_or(true, |min| price >= min);
                let max_ok = form_data.max_price.map_or(true, |max| price <= max);
                min_ok && max_ok
            };

            if matches_query && matches_category && matches_price {
                results.push((name, category, price));
            }
        }

        let results_html = if results.is_empty() {
            "<p>No products found matching your criteria.</p>".to_string()
        } else {
            let mut html = "<h2>Search Results</h2><ul>".to_string();
            for (name, category, price) in results {
                html.push_str(&format!(
                    "<li><strong>{}</strong> ({}): ${:.2}</li>",
                    name, category, price
                ));
            }
            html.push_str("</ul>");
            html
        };

        let response_html = format!(r#"
<!DOCTYPE html>
<html>
<head>
    <title>Search Results</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }}
        ul {{ list-style: none; padding: 0; }}
        li {{ padding: 10px; border: 1px solid #ddd; margin: 5px 0; border-radius: 4px; }}
        .search-info {{ background: #f8f9fa; padding: 15px; border-radius: 4px; margin-bottom: 20px; }}
        a {{ color: #3498db; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <h1>Search Results</h1>

    <div class="search-info">
        <p><strong>Search Query:</strong> "{}"</p>
        <p><strong>Category:</strong> {}</p>
        <p><strong>Price Range:</strong> {} - {}</p>
    </div>

    {}

    <p><a href="/search">← New Search</a> | <a href="/">Home</a></p>
</body>
</html>
"#,
            form_data.query,
            form_data.category.as_deref().unwrap_or("All"),
            form_data.min_price.map_or("Any".to_string(), |p| format!("${:.2}", p)),
            form_data.max_price.map_or("Any".to_string(), |p| format!("${:.2}", p)),
            results_html
        );

        Ok(Response::new(StatusCode::OK, response_html)
            .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8"))
    }
}

struct LoginEndpoint;

impl Endpoint for LoginEndpoint {
    async fn respond(&self, request: &mut Request) -> Result<Response> {
        match request.method() {
            &http::Method::GET => {
                let login_form = r#"
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 400px; margin: 0 auto; padding: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="password"] {
            width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;
        }
        button { background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; width: 100%; }
        button:hover { background: #2980b9; }
        .checkbox-group { display: flex; align-items: center; }
        .checkbox-group input { width: auto; margin-right: 10px; }
    </style>
</head>
<body>
    <h1>Login</h1>
    <form method="POST" action="/login">
        <div class="form-group">
            <label for="username">Username</label>
            <input type="text" id="username" name="username" required>
        </div>

        <div class="form-group">
            <label for="password">Password</label>
            <input type="password" id="password" name="password" required>
        </div>

        <div class="form-group">
            <div class="checkbox-group">
                <input type="checkbox" id="remember_me" name="remember_me" value="yes">
                <label for="remember_me">Remember me</label>
            </div>
        </div>

        <button type="submit">Login</button>
    </form>

    <p style="text-align: center; margin-top: 20px;">
        <a href="/register">Don't have an account? Register here</a>
    </p>
</body>
</html>
"#;

                Ok(Response::new(StatusCode::OK, login_form)
                    .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8"))
            }
            &http::Method::POST => {
                self.handle_login_submission(request).await
            }
            _ => Ok(Response::new(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed")),
        }
    }
}

impl LoginEndpoint {
    async fn handle_login_submission(&self, request: &mut Request) -> Result<Response> {
        let form_data: LoginForm = match request.into_form().await {
            Ok(data) => data,
            Err(_) => {
                return Ok(Response::new(StatusCode::BAD_REQUEST, "Invalid form data")
                    .header(http::header::CONTENT_TYPE, "text/plain"));
            }
        };

        println!("Login attempt: {:?}", form_data);

        // Simple authentication check (in real app, check against database)
        if form_data.username == "admin" && form_data.password == "password" {
            let message = format!(
                "Welcome back, {}! You have been logged in successfully.{}",
                form_data.username,
                if form_data.remember_me.is_some() { " (Session will be remembered)" } else { "" }
            );

            Ok(Response::new(StatusCode::OK, HtmlTemplates::success_page(&message))
                .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8")
                .header("Set-Cookie", "session=abc123; Path=/; HttpOnly"))
        } else {
            let error_form = r#"
<!DOCTYPE html>
<html>
<head>
    <title>Login - Error</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 400px; margin: 0 auto; padding: 20px; }
        .error { color: #e74c3c; background: #fdf2f2; padding: 10px; border-radius: 4px; margin-bottom: 15px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="password"] {
            width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;
        }
        button { background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; width: 100%; }
        button:hover { background: #2980b9; }
        .checkbox-group { display: flex; align-items: center; }
        .checkbox-group input { width: auto; margin-right: 10px; }
    </style>
</head>
<body>
    <h1>Login</h1>

    <div class="error">
        Invalid username or password. Please try again.
    </div>

    <form method="POST" action="/login">
        <div class="form-group">
            <label for="username">Username</label>
            <input type="text" id="username" name="username" required>
        </div>

        <div class="form-group">
            <label for="password">Password</label>
            <input type="password" id="password" name="password" required>
        </div>

        <div class="form-group">
            <div class="checkbox-group">
                <input type="checkbox" id="remember_me" name="remember_me" value="yes">
                <label for="remember_me">Remember me</label>
            </div>
        </div>

        <button type="submit">Login</button>
    </form>

    <p style="text-align: center; margin-top: 20px;">
        <small>Hint: Try username "admin" and password "password"</small><br>
        <a href="/register">Don't have an account? Register here</a>
    </p>
</body>
</html>
"#;

            Ok(Response::new(StatusCode::UNAUTHORIZED, error_form)
                .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8"))
        }
    }
}

// ============================================================================
// Example Usage and Demonstration
// ============================================================================

async fn demonstrate_forms() -> Result<()> {
    println!("\n=== Form Handling Demonstration ===");

    // Test contact form
    println!("\n--- Testing Contact Form ---");
    let contact_endpoint = ContactFormEndpoint;

    // GET request to show form
    let mut get_request = Request::get("/contact");
    let response = contact_endpoint.respond(&mut get_request).await?;
    println!("GET /contact: {}", response.status());

    // POST request with valid data
    let contact_data = "name=John+Doe&email=john@example.com&subject=Test+Subject&message=This+is+a+test+message+with+enough+content&newsletter=yes";
    let mut post_request = Request::post("/contact")
        .header(http::header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    post_request.replace_body(contact_data);

    let response = contact_endpoint.respond(&mut post_request).await?;
    println!("POST /contact (valid): {}", response.status());

    // POST request with invalid data
    let invalid_data = "name=&email=invalid-email&subject=&message=short";
    let mut invalid_request = Request::post("/contact")
        .header(http::header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    invalid_request.replace_body(invalid_data);

    let response = contact_endpoint.respond(&mut invalid_request).await?;
    println!("POST /contact (invalid): {}", response.status());

    // Test registration form
    println!("\n--- Testing Registration Form ---");
    let registration_endpoint = RegistrationEndpoint;

    let valid_registration = "username=newuser&email=new@example.com&password=SecurePass123&confirm_password=SecurePass123&age=25&terms=accepted";
    let mut reg_request = Request::post("/register")
        .header(http::header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    reg_request.replace_body(valid_registration);

    let response = registration_endpoint.respond(&mut reg_request).await?;
    println!("POST /register (valid): {}", response.status());

    // Test search form
    println!("\n--- Testing Search Form ---");
    let search_endpoint = SearchEndpoint;

    let mut search_request = Request::get("/search?query=laptop&category=electronics&min_price=500&max_price=1500&in_stock=yes");
    let response = search_endpoint.respond(&mut search_request).await?;
    println!("GET /search (with params): {}", response.status());

    // Test login form
    println!("\n--- Testing Login Form ---");
    let login_endpoint = LoginEndpoint;

    let valid_login = "username=admin&password=password&remember_me=yes";
    let mut login_request = Request::post("/login")
        .header(http::header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    login_request.replace_body(valid_login);

    let response = login_endpoint.respond(&mut login_request).await?;
    println!("POST /login (valid): {}", response.status());

    let invalid_login = "username=wronguser&password=wrongpass";
    let mut bad_login_request = Request::post("/login")
        .header(http::header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    bad_login_request.replace_body(invalid_login);

    let response = login_endpoint.respond(&mut bad_login_request).await?;
    println!("POST /login (invalid): {}", response.status());

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("HTTP-Kit Form Handling Example");
    println!("==============================");

    demonstrate_forms().await?;

    println!("\n=== Example Complete ===");
    println!("This example demonstrated:");
    println!("• HTML form rendering and submission");
    println!("• URL-encoded form data parsing");
    println!("• Form validation with error display");
    println!("• Different input types (text, email, password, number, checkbox, select)");
    println!("• Form processing patterns");
    println!("• Error handling and user feedback");
    println!("• GET/POST method handling");
    println!("• Content-Type header management");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_form_validation() {
        let valid_contact = ContactForm {
            name: "John Doe".to_string(),
            email: "john@example.com".to_string(),
            subject: "Test Subject".to_string(),
            message: "This is a valid message with enough content".to_string(),
            newsletter: Some("yes".to_string()),
        };

        let errors = FormValidator::validate_contact_form(&valid_contact);
        assert!(errors.is_empty());

        let invalid_contact = ContactForm {
            name: "".to_string(),
            email: "invalid-email".to_string(),
            subject: "".to_string(),
            message: "short".to_string(),
            newsletter: None,
        };

        let errors = FormValidator::validate_contact_form(&invalid_contact);
        assert!(!errors.is_empty());
        assert!(errors.contains_key("name"));
        assert!(errors.contains_key("email"));
        assert!(errors.contains_key("subject"));
        assert!(errors.contains_key("message"));
    }

    #[test]
    fn test_email_validation() {
        assert!(FormValidator::is_valid_email("test@example.com"));
        assert!(FormValidator::is_valid_email("user.name@domain.co.uk"));
        assert!(!FormValidator::is_valid_email("invalid-email"));
        assert!(!FormValidator::is_valid_email("@domain.com"));
        assert!(!FormValidator::is_valid_email("user@"));
        assert!(!FormValidator::is_valid_email("user"));
    }

    #[tokio::test]
    async fn test_contact_form_endpoint() -> Result<()> {
        let endpoint = ContactFormEndpoint;

        // Test GET request
        let mut get_request = Request::get("/contact");
        let response = endpoint.respond(&mut get_request).await?;
        assert_eq!(response.status(), StatusCode::OK);

        // Test POST with valid data
        let form_data = "name=Test+User&email=test@example.com&subject=Test&message=This+is+a+test+message+with+content";
        let mut post_request = Request::post("/contact")
            .header(http::header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        post_request.replace_body(form_data);

        let response = endpoint.respond(&mut post_request).await?;
        assert_eq!(response.status(), StatusCode::OK);

        Ok(())
    }

    #[tokio::test]
    async fn test_registration_endpoint() -> Result<()> {
        let endpoint = RegistrationEndpoint;

        let valid_data = "username=testuser&email=test@example.com&password=SecurePass123&confirm_password=SecurePass123&age=25&terms=accepted";
        let mut request = Request::post("/register")
            .header(http::header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        request.replace_body(valid_data);

        let response = endpoint.respond(&mut request).await?;
        assert_eq!(response.status(), StatusCode::OK);

        Ok(())
    }

    #[tokio::test]
    async fn test_search_endpoint() -> Result<()> {
        let endpoint = SearchEndpoint;

        // Test GET without query (show form)
        let mut get_request = Request::get("/search");
        let response = endpoint.respond(&mut get_request).await?;
        assert_eq!(response.status(), StatusCode::OK);

        // Test GET with query
        let mut search_request = Request::get("/search?query=test&category=electronics");
        let response = endpoint.respond(&mut search_request).await?;
        assert_eq!(response.status(), StatusCode::OK);

        Ok(())
    }

    #[tokio::test]
    async fn test_login_endpoint() -> Result<()> {
        let endpoint = LoginEndpoint;

        // Test valid login
        let valid_data = "username=admin&password=password";
        let mut request = Request::post("/login")
            .header(http::header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        request.replace_body(valid_data);

        let response = endpoint.respond(&mut request).await?;
        assert_eq!(response.status(), StatusCode::OK);

        // Test invalid login
        let invalid_data = "username=wrong&password=wrong";
        let mut bad_request = Request::post("/login")
