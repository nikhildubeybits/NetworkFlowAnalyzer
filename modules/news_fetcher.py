# modules/news_fetcher.py
import requests

def get_cyber_news(api_key):
    """
    Fetches the latest cybersecurity news from NewsAPI.
    """
    if not api_key:
        return {"error": "News API key is not configured.", "articles": []}

    # Construct the URL to search for recent articles on cybersecurity topics
    # Construct the URL to search for recent articles on cybersecurity and IT topics from specific sources
    domains = (
        'thehackernews.com,'
        'bleepingcomputer.com,'
        'darkreading.com,'
        'krebsonsecurity.com,'
        'wired.com,'
        'arstechnica.com,'
        'zdnet.com'
    )
    url = (
        'https://newsapi.org/v2/everything?'
        'q=("cybersecurity" OR "information technology" OR "information security" OR "hacking" OR "data breach" OR "vulnerability" OR "malware" OR "ransomware" OR "phishing")&'
        f'domains={domains}&'
        'sortBy=publishedAt&'
        'language=en&'
        f'apiKey={api_key}'
    )
    
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
        data = response.json()
        
        # Return the first 5 articles to keep the dashboard clean
        return {"articles": data.get('articles', [])[:5]}
    except requests.exceptions.RequestException as e:
        print(f"Error fetching news: {e}")
        return {"error": f"Could not fetch news from the provider. Please check API key and network.", "articles": []}
