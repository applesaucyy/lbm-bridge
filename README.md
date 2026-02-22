## The bridging system for the [Leaflet Blog Manager](https://github.com/applesaucyy/lbm)

This is mainly for people who want to self host the template on their own servers. put these 2 files in the same folder as the `index.html`, `logic.js`, and `style.css`, and change the `MASTER_KEY` to a secure password 
(and update your `.htaccess` rules to make sure people cant just load it in on the browser itself)

`UPLOAD_ENDPOINT` is the location of the api file, so make sure you also edit this `const` if you put `api.php` into another folder

