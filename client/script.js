document.querySelector('.login-button').addEventListener('click', function () {
    const username = document.querySelector('input[type="text"]').value;
    const password = document.querySelector('input[type="password"]').value;
  
    if (!username || !password) {
        alert('Калі ласка, увядзіце лагін і пароль!');
        return;
    }
  
    // Запыт на сервер для праверкі лагіна
    fetch('https://vilija.onrender.com/login', {  // Тут выкарыстоўваем ваш сервэр на Render
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ username, password }),
    })
      .then(response => response.json())
      .then(data => {
        if (data.success) {
          alert("Вітаем, " + username + "!");
          window.location.href = '/chat';  // Напрамак на старонку чату
        } else {
          alert('Няправільны лагін або пароль');
        }
      })
      .catch(error => {
        console.error("Памылка злучэння:", error);
        alert('Не атрымалася падключыцца да сервера!');
      });
  });

  