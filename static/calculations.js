document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('accessToken');
    if (!token) {
        window.location.href = '/static/login.html';
        return;
    }

    const calcForm = document.getElementById('calcForm');
    const calcList = document.getElementById('calcList');
    const messageDiv = document.getElementById('message');
    const calcIdInput = document.getElementById('calcId');
    const cancelEditBtn = document.getElementById('cancelEditBtn');

    const headers = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
    };
    const fetchCalculations = async () => {
        try {
            const response = await fetch('/calculations/', { headers });
            if (!response.ok) throw new Error('Could not fetch calculations.');
            
            const calculations = await response.json();
            calcList.innerHTML = ''; 
            calculations.forEach(calc => {
                const li = document.createElement('li');
                li.innerHTML = `
                    <span>${calc.a} ${calc.type} ${calc.b} = ${calc.result}</span>
                    <div>
                        <button class="edit-btn" data-id="${calc.id}">Edit</button>
                        <button class="delete-btn" data-id="${calc.id}">Delete</button>
                    </div>
                `;
                calcList.appendChild(li);
            });
        } catch (error) {
            messageDiv.textContent = error.message;
            messageDiv.style.color = 'red';
        }
    };
    calcForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const a = parseFloat(document.getElementById('valA').value);
        const b = parseFloat(document.getElementById('valB').value);
        const type = document.getElementById('opType').value;
        const id = calcIdInput.value;

        if (type === 'divide' && b === 0) {
            messageDiv.textContent = 'Cannot divide by zero.';
            messageDiv.style.color = 'red';
            return;
        }

        const url = id ? `/calculations/${id}` : '/calculations/';
        const method = id ? 'PUT' : 'POST';

        try {
            const response = await fetch(url, {
                method,
                headers,
                body: JSON.stringify({ a, b, type })
            });
            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.detail);
            }
            resetForm();
            fetchCalculations();
        } catch (error) {
            messageDiv.textContent = error.message;
            messageDiv.style.color = 'red';
        }
    });

    calcList.addEventListener('click', async (e) => {
        const target = e.target;
        const id = target.dataset.id;

        if (target.classList.contains('delete-btn')) {
            if (!confirm('Are you sure you want to delete this calculation?')) return;
            try {
                const response = await fetch(`/calculations/${id}`, { method: 'DELETE', headers });
                if (!response.ok) throw new Error('Could not delete calculation.');
                fetchCalculations();
            } catch (error) {
                messageDiv.textContent = error.message;
            }
        }

        if (target.classList.contains('edit-btn')) {
            try {
                const response = await fetch(`/calculations/${id}`, { headers });
                if (!response.ok) throw new Error('Could not fetch calculation details.');
                const calc = await response.json();
                
                document.getElementById('calcId').value = calc.id;
                document.getElementById('valA').value = calc.a;
                document.getElementById('valB').value = calc.b;
                document.getElementById('opType').value = calc.type;
                cancelEditBtn.style.display = 'inline-block';
            } catch (error) {
                messageDiv.textContent = error.message;
            }
        }
    });

    cancelEditBtn.addEventListener('click', resetForm);

    function resetForm() {
        calcForm.reset();
        calcIdInput.value = '';
        cancelEditBtn.style.display = 'none';
        messageDiv.textContent = '';
    }

    fetchCalculations();
});