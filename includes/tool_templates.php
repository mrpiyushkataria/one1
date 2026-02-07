<?php
// Tool command templates (edit here anytime)
// Placeholders supported:
// {company_slug} {project_slug} {root_domain} {out_dir}
// {subdomains_file} {resolved_file} {alive_file} {nmap_xml}
// {project_id}

function slugify(string $s): string {
  $s = strtolower(trim($s));
  $s = preg_replace('/[^a-z0-9]+/', '-', $s);
  return trim($s, '-');
}

function render_tpl(string $tpl, array $vars): string {
  return strtr($tpl, array_combine(
    array_map(fn($k)=>'{'.$k.'}', array_keys($vars)),
    array_values($vars)
  ));
}

function project_vars(array $project, string $root_domain): array {
  $company_slug = slugify($project['company_name'] ?? 'company');
  $project_slug = slugify($project['title'] ?? 'project');
  $root_slug    = slugify($root_domain);

  // user runs commands on Kali/Mac locally
  $out_dir = "inseclabs_out/{$company_slug}/{$project_slug}/{$root_slug}";
  return [
    'project_id'      => (string)($project['id'] ?? '0'),
    'company_slug'    => $company_slug,
    'project_slug'    => $project_slug,
    'root_domain'     => $root_domain,
    'out_dir'         => $out_dir,
    'subdomains_file' => "{$out_dir}/subdomains.txt",
    'resolved_file'   => "{$out_dir}/resolved.txt",
    'alive_file'      => "{$out_dir}/alive.txt",
    'nmap_xml'        => "{$out_dir}/nmap.xml",
  ];
}

// Profiles: low / medium / high / aggressive
function templates(): array {
  return [
    [
      'tool' => 'subfinder',
      'step' => 'Subdomains',
      'key'  => 'subdomains',
      'desc' => 'Collect subdomains (authorized scope only).',
      'profiles' => [
        'low' => [
          "mkdir -p {out_dir}",
          "subfinder -silent -d {root_domain} -o {out_dir}/subdomains_subfinder.txt",
          "cat {out_dir}/subdomains_subfinder.txt | sort -u > {subdomains_file}",
        ],
        'medium' => [
          "mkdir -p {out_dir}",
          "subfinder -silent -d {root_domain} --all --recursive -o {out_dir}/subdomains_subfinder.txt",
          "cat {out_dir}/subdomains_subfinder.txt | sort -u > {subdomains_file}",
        ],
        'high' => [
          "mkdir -p {out_dir}",
          "subfinder -silent -d {root_domain} --all --recursive -o {out_dir}/subdomains_subfinder.txt",
          "assetfinder --subs-only {root_domain} 2>/dev/null | tee {out_dir}/subdomains_assetfinder.txt >/dev/null",
          "cat {out_dir}/subdomains_subfinder.txt {out_dir}/subdomains_assetfinder.txt | sort -u > {subdomains_file}",
        ],
        'aggressive' => [
          "mkdir -p {out_dir}",
          "subfinder -silent -d {root_domain} --all --recursive -o {out_dir}/subdomains_subfinder.txt",
          "amass enum -passive -d {root_domain} -o {out_dir}/subdomains_amass.txt",
          "assetfinder --subs-only {root_domain} 2>/dev/null | tee {out_dir}/subdomains_assetfinder.txt >/dev/null",
          "cat {out_dir}/subdomains_subfinder.txt {out_dir}/subdomains_amass.txt {out_dir}/subdomains_assetfinder.txt | sort -u > {subdomains_file}",
        ],
      ]
    ],

    [
      'tool' => 'dnsx',
      'step' => 'Resolve',
      'key'  => 'dnsx',
      'desc' => 'Resolve subdomains to IPs (needed to link subdomain → host in graph).',
      'profiles' => [
        'low' => [
          "cat {subdomains_file} | dnsx -silent -a -resp -o {resolved_file}",
        ],
        'medium' => [
          "cat {subdomains_file} | dnsx -silent -a -resp -retry 2 -o {resolved_file}",
        ],
        'high' => [
          "cat {subdomains_file} | dnsx -silent -a -resp -retry 2 -threads 200 -o {resolved_file}",
        ],
        'aggressive' => [
          "cat {subdomains_file} | dnsx -silent -a -resp -retry 3 -threads 500 -o {resolved_file}",
        ],
      ]
    ],

    [
      'tool' => 'httpx',
      'step' => 'Alive',
      'key'  => 'httpx',
      'desc' => 'Find alive hosts and save “alive.txt” (recommended before nmap).',
      'profiles' => [
        'low' => [
          "cat {subdomains_file} | httpx -silent -status-code -title -o {out_dir}/httpx.txt",
          "cat {out_dir}/httpx.txt | awk '{print $1}' | sort -u > {alive_file}",
        ],
        'medium' => [
          "cat {subdomains_file} | httpx -silent -status-code -title -ip -o {out_dir}/httpx.txt",
          "cat {out_dir}/httpx.txt | awk '{print $1}' | sort -u > {alive_file}",
        ],
        'high' => [
          "cat {subdomains_file} | httpx -silent -status-code -title -ip -tech-detect -o {out_dir}/httpx.txt",
          "cat {out_dir}/httpx.txt | awk '{print $1}' | sort -u > {alive_file}",
        ],
        'aggressive' => [
          "cat {subdomains_file} | httpx -silent -status-code -title -ip -tech-detect -follow-redirects -o {out_dir}/httpx.txt",
          "cat {out_dir}/httpx.txt | awk '{print $1}' | sort -u > {alive_file}",
        ],
      ]
    ],

    [
      'tool' => 'nmap',
      'step' => 'Nmap',
      'key'  => 'nmap',
      'desc' => 'Nmap XML upload supports multiple files. Use alive.txt or subdomains.txt as input.',
      'profiles' => [
        'low' => [
          "nmap -sV -T3 -Pn -iL {alive_file} -oX {nmap_xml}",
        ],
        'medium' => [
          "nmap -sV -sC -T3 -Pn -iL {alive_file} -oX {nmap_xml}",
        ],
        'high' => [
          "nmap -sV -sC -T4 -Pn -iL {alive_file} -oX {nmap_xml}",
        ],
        'aggressive' => [
          // Use only if program allows high rate / heavy scanning
          "nmap -sV -sC -T4 -Pn --reason -iL {alive_file} -oX {nmap_xml}",
        ],
      ]
    ],

    // --- WEB CONTENT / URL DISCOVERY ---
    [
      'tool' => 'gau',
      'step' => 'URLs (gau)',
      'key'  => 'wayback',
      'desc' => 'Collect historical URLs (gau). Upload output as Wayback/URLs.',
      'profiles' => [
        'low' => [
          "gau --subs {root_domain} | sort -u > {out_dir}/gau_urls.txt",
        ],
        'medium' => [
          "gau --subs {root_domain} --threads 20 | sort -u > {out_dir}/gau_urls.txt",
        ],
        'high' => [
          "gau --subs {root_domain} --threads 40 | sort -u > {out_dir}/gau_urls.txt",
        ],
        'aggressive' => [
          "gau --subs {root_domain} --threads 50 --providers wayback,commoncrawl,otx,urlscan | sort -u > {out_dir}/gau_urls.txt",
        ],
      ]
    ],

    [
      'tool' => 'katana',
      'step' => 'Crawl (katana)',
      'key'  => 'wayback',
      'desc' => 'Fast crawler for live URLs. Upload output as Wayback/URLs.',
      'profiles' => [
        'low' => [
          "katana -silent -u https://{root_domain} -d 2 -o {out_dir}/katana.txt",
        ],
        'medium' => [
          "katana -silent -u https://{root_domain} -d 3 -jc -kf -o {out_dir}/katana.txt",
        ],
        'high' => [
          "katana -silent -u https://{root_domain} -d 4 -jc -kf -ct 2 -o {out_dir}/katana.txt",
        ],
        'aggressive' => [
          "katana -silent -u https://{root_domain} -d 5 -jc -kf -ct 2 -c 20 -p 20 -o {out_dir}/katana.txt",
        ],
      ]
    ],

    // --- PORT SCANNING (FAST) ---
    [
      'tool' => 'naabu',
      'step' => 'Ports (naabu)',
      'key'  => 'other',
      'desc' => 'Fast port scan before Nmap. (Upload output as raw file for now.)',
      'profiles' => [
        'low' => [
          "naabu -silent -l {resolved_file} -top-ports 100 -o {out_dir}/naabu.txt",
        ],
        'medium' => [
          "naabu -silent -l {resolved_file} -top-ports 1000 -rate 2000 -o {out_dir}/naabu.txt",
        ],
        'high' => [
          "naabu -silent -l {resolved_file} -p - -rate 5000 -o {out_dir}/naabu_all.txt",
        ],
        'aggressive' => [
          "naabu -silent -l {resolved_file} -p - -rate 10000 -retries 2 -o {out_dir}/naabu_all.txt",
        ],
      ]
    ],

    // --- FUZZING / CONTENT DISCOVERY ---
    [
      'tool' => 'ffuf',
      'step' => 'Fuzz (ffuf)',
      'key'  => 'other',
      'desc' => 'Content discovery. Save JSON and upload raw output as file.',
      'profiles' => [
        'low' => [
          "ffuf -w /usr/share/wordlists/dirb/common.txt -u https://{root_domain}/FUZZ -fc 404 -o {out_dir}/ffuf.json -of json",
        ],
        'medium' => [
          "ffuf -w /usr/share/wordlists/dirb/common.txt -u https://{root_domain}/FUZZ -t 50 -fc 404 -o {out_dir}/ffuf.json -of json",
        ],
        'high' => [
          "ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u https://{root_domain}/FUZZ -t 80 -fc 404 -o {out_dir}/ffuf.json -of json",
        ],
        'aggressive' => [
          "ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u https://{root_domain}/FUZZ -t 120 -fc 404 -recursion -recursion-depth 2 -o {out_dir}/ffuf.json -of json",
        ],
      ]
    ],

    // --- VULN SCANNING ---
    [
      'tool' => 'nuclei',
      'step' => 'Vulns (nuclei)',
      'key'  => 'other',
      'desc' => 'Template-based vuln scan (authorized only). Save JSON for parsing in future.',
      'profiles' => [
        'low' => [
          "nuclei -silent -l {alive_file} -severity low,medium -o {out_dir}/nuclei.txt",
        ],
        'medium' => [
          "nuclei -silent -l {alive_file} -severity low,medium,high -o {out_dir}/nuclei.txt",
        ],
        'high' => [
          "nuclei -silent -l {alive_file} -severity medium,high,critical -rl 50 -o {out_dir}/nuclei.txt",
        ],
        'aggressive' => [
          "nuclei -silent -l {alive_file} -severity medium,high,critical -rl 100 -bulk-size 25 -o {out_dir}/nuclei.txt",
        ],
      ]
    ],
  ];
}
