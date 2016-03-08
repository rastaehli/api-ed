api editor
=============

This project contains my solution for a web application to display and edit REST-compliant API documentation.

The immediate use cases relevant to this project are:
1) View all the API calls at left, a list of (up to ten) most recently added calls at right.
2) Click a call to see a detailed description of how to use the call, with examples.
3) Log in to the site to see the same views with the addition of an "add/edit/delete" buttons for a call and for detail fields.
5) Click "add" or "delete" to add/delete calls.
6) Click "edit" to change the name or description fields for a call.

The current functionality is demonstrated by running the code in api_ed_ws.py.  Here’s how:

- clone this project to your machine and change to the project directory:
- launch the virtual machine and enter a virtual terminal:
<pre>    
    vagrant up
    vagrant ssh
</pre>
- in the VM, cd to vagrant project folder and create the (empty) database, then quit psql:
<pre>    
    cd /vagrant
    psql
    \i create_db.sql
    \q
</pre>
- Populate the database with tables and data:
<pre>    
    python orm.py
    python db_data.py
</pre>
- Start the web service:
<pre>
	python web_service.py
</pre>
Open the application in a browser: 
<pre>
	http://localhost:5000/api/all
</pre>
