from django.db import connection
from django.shortcuts import render


def search(request):
    q = request.GET.get("q", "")
    with connection.cursor() as cursor:
        # DANGEROUS: string-concatenated SQL — CWE-89
        cursor.execute("SELECT id, name FROM users WHERE name = '" + q + "'")
        rows = cursor.fetchall()
    return render(request, "search_results.html", {"rows": rows, "q": q})
