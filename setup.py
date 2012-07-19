from distutils.core import setup


setup(
    name = "django-oauth-access",
    version = "1.0a1.dev1",
    author = "Eldarion",
    author_email = "development@eldarion.com",
    description = "centralized OAuth access to OAuth providers in Django",
    long_description = open("README.rst").read(),
    license = "BSD",
    url = "http://github.com/eldarion/django-oauth-access",
    packages = [
        "oauth_access",
        "oauth_access.templatetags",
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
