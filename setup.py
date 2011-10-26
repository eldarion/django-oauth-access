from distutils.core import setup



setup(
    name = "django-oauth-access",
    version = "0.1.dev21",
    author = "Eldarion",
    author_email = "development@eldarion.com",
    description = "centralized oAuth access to oAuth providers in Django",
    long_description = open("README.rst").read(),
    license = "BSD",
    url = "http://github.com/eldarion/django-oauth-access",
    packages = [
        "oauth_access",
        "oauth_access.templatetags",
        "oauth_access.utils",
    ],
    classifiers = [
        "Development Status :: 3 - Alpha",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Framework :: Django",
    ]
)
