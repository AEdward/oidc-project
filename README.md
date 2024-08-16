An OIDC proof of concept Django project. 
Make sure you have the .env file and place it in the project directory (```oidc_project/.env```)
Please also make sure you have a virtual env(venv) and install all the requirements on ```requirements.txt```

Finally, to run the Django app: 
    ```python manage.py runserver 3000```  

    
The ```3000``` stands for the port. Since this is a local testing server, the port depends on the port that your local app is running on. The port should also match the port of the redirect URI that has been added to eSignet DB with your specific client ID.
