from flask import Flask, render_template, request, make_response

app = Flask(__name__)
application = app


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/headers')
def headers():
    return render_template('requestInfo.html', header='Заголовки', data=request.headers)


@app.route('/cookies')
def cookies():
    response = make_response()
    if "Pum pum" in request.cookies:
        response.delete_cookie("Pum pum")
    else:
        response.set_cookie("Pum pum", "Hello")
    response.set_data(render_template('requestInfo.html', header='cookies', data=request.cookies))
    return response


@app.route('/url_params')
def url_params():
    return render_template('requestInfo.html', header='url_params', data=request.args)


@app.route('/form', methods=['GET', 'POST'])
def form():
    return render_template('form.html')


@app.route('/phone', methods=['GET', 'POST'])
def phone():
    if request.method == 'GET':
         return render_template('phone.html')

    result = ""
    errors = []
    if request.method == "POST":
        num = request.form.get('phone_number', '')
        cleaned_number = ''.join(filter(lambda x: x.isdigit(), num))
        if len(cleaned_number) not in (10, 11):
            errors.append("Неверное количество цифр.")

        if not all(char.isdigit() or char in '+()-. ' for char in num):
            errors.append("В номере телефона встречаются недопустимые символы.")

        if not errors:
            result = ('8-' + cleaned_number[-10:-7] + '-' + cleaned_number[-7:-4] + '-'
                            + cleaned_number[-4:-2] + '-' + cleaned_number[-2:])

    return render_template('phone.html', phone_number=result, errors=errors)

if __name__ == '__main__':
    app.run(debug=True)