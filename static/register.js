document.getElementById('registerForm').addEventListener('submit', async (event) => {
    event.preventDefault();

    const username = document.getElementById('username').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const messageDiv = document.getElementById('message');

    if (password.length < 8) {
        messageDiv.textContent = 'Password must be at least 8 characters long.';
        messageDiv.style.color = 'red';
        return;
    }

    try {
        const response = await fetch('/register', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ username, email, password }),
        });

        if (response.ok) {
            messageDiv.textContent = 'Registration successful! You can now log in.';
            messageDiv.style.color = 'green';
            document.getElementById('registerForm').reset();
        } else {
            const errorData = await response.json();
            messageDiv.textContent = `Error: ${errorData.detail}`;
            messageDiv.style.color = 'red';
        }
    } catch (error) {
        messageDiv.textContent = 'An unexpected error occurred.';
        messageDiv.style.color = 'red';
    }
});