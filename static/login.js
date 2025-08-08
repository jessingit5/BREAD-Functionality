document.getElementById('loginForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const messageDiv = document.getElementById('message');

    try {
        const response = await fetch('/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ email, password }),
        });

        if (response.ok) {
            const data = await response.json();
            localStorage.setItem('accessToken', data.access_token);
            window.location.href = '/static/calculations.html';
            messageDiv.textContent = 'Login successful!';
            messageDiv.style.color = 'green';
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