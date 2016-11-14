# Multi-User Blog Project

## Description

Using Google App Engine, I built a multi-user blog with the following functions:

* Basic Blog
    * Front Page with up to 10 entries
    * A form to submit a new entry
    * Each Post has its own permalink

* User Registration
    * Validates User input and error handling
    * Welcomes user after successful registration
    * Store passwords securely

* Login
    * Validates User input and error handling
    * Also redirects User to welcome page upon successful login

* Logout
    * Cookie is cleared and redirected to signup page

* Other Features:
    * Can edit/delete your own posts, but not the posts of others
    * Can like/unlike posts, but not of your own
    * Can comment on individual posts as well as edit the comment, but can not edit other users' comments.

## Instructions:

Visit [https://mhardwick-blog-project.appspot.com/](https://mhardwick-blog-project.appspot.com/)

Or download/clone this repo and install the necessary dependencies with:

    bower install

You will need Python 2.7 and Google Cloud SDK installed as well, once your App engine account is set up you will need to follow Google's instructions for your specific system. In Ubuntu or Windows bash, simply:

    cd /directory
    dev_appserver.py .


