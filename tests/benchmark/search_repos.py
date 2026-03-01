"""Search GitHub for popular AI framework repositories."""
import httpx
import time

frameworks = [
    ('vertex ai agent builder', 'python'),
    ('google gemini agent', 'python'),
    ('google adk python', 'python'),
    ('gemini function calling', 'python'),
    ('aws bedrock agent', 'python'),
    ('amazon bedrock langchain', 'python'),
    ('boto3 bedrock runtime', 'python'),
    ('bedrock claude agent', 'python'),
]

print('Searching GitHub for popular AI repos...\n')

for query, lang in frameworks:
    url = f'https://api.github.com/search/repositories?q={query}+language:{lang}&sort=stars&order=desc&per_page=5'
    try:
        resp = httpx.get(url, timeout=15)
        data = resp.json()
        print(f'=== {query.upper()} ===')
        for item in data.get('items', [])[:5]:
            desc = (item.get('description') or 'No description')[:70]
            name = item['full_name']
            stars = item['stargazers_count']
            url = item['html_url']
            print(f"  {name}")
            print(f"    Stars: {stars:,} | {desc}")
            print(f"    URL: {url}")
        print()
        time.sleep(0.5)  # Rate limiting
    except Exception as e:
        print(f'Error searching {query}: {e}')
