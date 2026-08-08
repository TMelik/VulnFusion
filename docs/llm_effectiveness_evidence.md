# Proving the Value of LLM Deduplication

## English

### The main idea

VulnFusion is not a single prompt placed on top of scanner output.

It is a security pipeline that:

- reads results from different scanners;
- converts them into one common format;
- keeps the original evidence and scanner names;
- merges clear duplicates with deterministic rules;
- asks an LLM only about difficult pairs;
- keeps uncertain findings separate for human review.

The LLM has a small but important role: it helps when two scanner findings are
similar in meaning, but simple rules cannot safely decide whether they describe
the same vulnerability.

### What we need to compare

We should run the same scanner findings in three modes:

| Mode | What it does |
|---|---|
| Raw scanner results | Shows every finding without deduplication |
| Deterministic only | Uses normalization and fixed deduplication rules |
| VulnFusion with LLM | Uses fixed rules first and the LLM only for ambiguous pairs |

For every mode, we should show:

- the number of findings before and after deduplication;
- false merges: different vulnerabilities incorrectly merged together;
- false splits: one vulnerability incorrectly left as several findings;
- the number of correct clusters;
- findings that need human review;
- analyst review time;
- LLM calls, latency, cache hits, and estimated cost.

False merges are especially important. In security work, hiding two different
vulnerabilities inside one record can be more dangerous than leaving one
vulnerability as two records.

### Simple examples that show the value

#### 1. A useful LLM merge

Two scanners use different names:

```text
ZAP:    SQL Injection
Nuclei: SQL Injection in search parameter
```

The endpoint, HTTP method, and vulnerable parameter are the same. Fixed string
rules may be unsure, but the LLM can use the shared technical details and
recommend a merge.

#### 2. Preventing a dangerous merge

Two findings have almost the same title, but they affect different endpoints or
parameters. A simple name-based deduplicator may merge them incorrectly.
VulnFusion gives the model the concrete endpoint, path, method, parameter,
service, CVE, and scanner identity. A conflict in these anchors should result in
no merge.

#### 3. Keeping uncertainty visible

If the model says the findings are probably the same but its confidence is below
`0.85`, VulnFusion does not merge them. Both findings receive a `needs_review`
status. A human can see the confidence, reason, suggested title, and review
candidates.

### Why one large prompt is not enough

A prompt such as this is useful for a quick experiment:

> Here are the results from five scanners. Deduplicate and prioritize them.

But it does not provide a reliable system. A single prompt does not guarantee:

- a common format for different scanners;
- stable finding identifiers;
- preservation of scanner evidence;
- clear source and scanner provenance;
- deterministic handling of obvious duplicates;
- strict structured JSON output;
- a fixed confidence threshold;
- safe behavior after a timeout or invalid response;
- a versioned cache;
- stable results when finding order changes;
- history comparison between scans;
- safe report and DefectDojo export.

A large prompt can also lose evidence, rename findings, produce a different
answer on another run, or become expensive when the report is large.

The project message should be:

> VulnFusion is a deterministic security pipeline. It uses an LLM as a limited
> reasoning component only when scanner evidence is ambiguous.

### A fair benchmark

To prove the benefit, we need a labeled dataset with:

- 50–100 finding pairs;
- 10–20 multi-finding cluster cases;
- findings from ZAP, Nuclei, Wapiti, Nikto, and Nmap;
- clear duplicates;
- clearly different vulnerabilities;
- difficult and uncertain pairs.

The same dataset should be tested with:

1. raw scanner output;
2. deterministic deduplication;
3. one large deduplication prompt;
4. VulnFusion Structured LLM Dedup.

The model, input data, and evaluation labels should be recorded so that another
person can repeat the experiment.

### What the current evaluation proves

The current `utils.dedup_evaluation` suite uses an Oracle client that knows the
expected labels. This is useful: it proves that candidate handling, clustering,
provenance, and evaluation metrics work correctly.

However, it does **not** yet prove that a live LLM makes better decisions. That
requires the separate live benchmark described above.

### What a strong demo should show

A report should present a simple comparison:

```text
Raw scanner output       27 findings
Deterministic dedup       22 findings
VulnFusion                18 findings
                          3 AI-confirmed clusters
                          2 findings need review
```

The demo should then open three real examples:

- one correct LLM merge;
- one incorrect merge prevented by VulnFusion;
- one uncertain pair sent for human review.

This is stronger evidence than only showing a final, smaller finding count.

---

## Հայերեն

### Հիմնական գաղափարը

VulnFusion-ը սկաներների արդյունքների վրա ավելացված մեկ մեծ prompt չէ։

Այն անվտանգության մշակման ամբողջական հոսք է, որը՝

- կարդում է տարբեր սկաներների արդյունքները,
- բերում է դրանք մեկ ընդհանուր ձևաչափի,
- պահպանում է սկզբնական ապացույցներն ու սկաների անունը,
- պարզ կրկնօրինակները միավորում է հստակ կանոններով,
- LLM-ին հարցնում է միայն բարդ զույգերի մասին,
- կասկածելի արդյունքները պահում է առանձին՝ մարդու ստուգման համար։

LLM-ի դերը փոքր է, բայց կարևոր։ Այն օգնում է այն դեպքերում, երբ երկու finding
իմաստով նման են, բայց պարզ կանոնները չեն կարող անվտանգ որոշել՝ դրանք նույն
խոցելիությո՞ւնն են, թե՞ ոչ։

### Ինչ պետք է համեմատենք

Նույն սկանավորման արդյունքները պետք է աշխատեցնենք երեք ռեժիմով։

| Ռեժիմ | Ինչ է անում |
|---|---|
| Սկաներների սկզբնական արդյունքներ | Ցույց է տալիս բոլոր finding-ները՝ առանց միավորման |
| Միայն հստակ կանոններ | Օգտագործում է normalization և deterministic deduplication |
| VulnFusion + LLM | Սկզբում կիրառում է հստակ կանոնները, հետո LLM-ին տալիս է միայն անորոշ զույգերը |

Յուրաքանչյուր ռեժիմի համար պետք է ցույց տալ՝

- քանի finding կար սկզբում և վերջում,
- false merge-երի քանակը՝ երբ տարբեր խոցելիություններ սխալմամբ միավորվել են,
- false split-երի քանակը՝ երբ նույն խոցելիությունը մնացել է մի քանի finding,
- ճիշտ խմբերի քանակը,
- մարդու ստուգում պահանջող finding-ները,
- վերլուծաբանի ծախսած ժամանակը,
- LLM հարցումների քանակը, արագությունը, cache hit-երը և մոտավոր արժեքը։

False merge-ը հատկապես վտանգավոր է։ Անվտանգության աշխատանքում երկու տարբեր
խոցելիություն մեկ finding-ի մեջ թաքցնելը կարող է ավելի վատ լինել, քան նույն
խոցելիությունը ժամանակավորապես երկու finding պահելը։

### Պարզ օրինակներ, որոնք ցույց են տալիս օգուտը

#### 1. Օգտակար LLM միավորում

Երկու սկաներ օգտագործում են տարբեր անուններ։

```text
ZAP:    SQL Injection
Nuclei: SQL Injection in search parameter
```

Endpoint-ը, HTTP method-ը և խոցելի parameter-ը նույնն են։ Միայն տեքստային
համեմատությունը կարող է չհասկանալ, որ դրանք նույն խնդիրն են։ LLM-ը կարող է
օգտագործել ընդհանուր տեխնիկական տվյալները և առաջարկել միավորում։

#### 2. Վտանգավոր միավորման կանխում

Երկու finding կարող են գրեթե նույն անունն ունենալ, բայց վերաբերվել տարբեր
endpoint-ների կամ parameter-ների։ Անունների պարզ համեմատությունը կարող է
սխալմամբ միավորել դրանք։ VulnFusion-ը մոդելին տալիս է endpoint-ը, path-ը,
method-ը, parameter-ը, service-ը, CVE-ն և սկաների ներքին ID-ն։ Եթե այս տվյալները
հակասում են իրար, finding-ները չպետք է միավորվեն։

#### 3. Անորոշությունը տեսանելի պահելը

Եթե մոդելը կարծում է, որ finding-ները նույնն են, բայց confidence-ը `0.85`-ից
ցածր է, VulnFusion-ը դրանք չի միավորում։ Երկուսն էլ ստանում են `needs_review`
կարգավիճակ։ Մարդը տեսնում է confidence-ը, պատճառը, առաջարկվող անունը և review
candidate-ները։

### Ինչու մեկ մեծ prompt-ը բավարար չէ

Այսպիսի prompt-ը հարմար է արագ փորձի համար։

> Ահա հինգ սկաների արդյունքները։ Միավորիր կրկնօրինակները և դասավորիր ըստ
> կարևորության։

Բայց սա հուսալի համակարգ չէ։ Մեկ prompt-ը չի երաշխավորում՝

- տարբեր սկաներների համար ընդհանուր ձևաչափ,
- կայուն finding ID-ներ,
- սկաների սկզբնական ապացույցների պահպանում,
- finding-ի աղբյուրի հստակ պահպանում,
- պարզ կրկնօրինակների deterministic մշակում,
- խիստ JSON պատասխան,
- հաստատուն confidence threshold,
- անվտանգ վարք timeout-ի կամ սխալ պատասխանի դեպքում,
- versioned cache,
- նույն արդյունքը finding-ների հերթականությունը փոխելիս,
- տարբեր սկանավորումների պատմական համեմատություն,
- անվտանգ report և DefectDojo export։

Մեծ prompt-ը կարող է նաև կորցնել ապացույցները, փոխել finding-ի անունը, հաջորդ
անգամ տալ ուրիշ պատասխան կամ թանկ լինել մեծ report-ի դեպքում։

Մեր հիմնական միտքը պետք է լինի՝

> VulnFusion-ը deterministic անվտանգության pipeline է։ Այն LLM-ն օգտագործում է
> որպես սահմանափակ reasoning բաղադրիչ՝ միայն անորոշ դեպքերի համար։

### Արդար benchmark

Օգուտը ապացուցելու համար մեզ պետք է նշված ճիշտ պատասխաններով dataset։ Այն
պետք է ունենա՝

- 50–100 finding զույգ,
- 10–20 բազմա-finding խմբային դեպք,
- ZAP, Nuclei, Wapiti, Nikto և Nmap արդյունքներ,
- պարզ կրկնօրինակներ,
- հստակ տարբեր խոցելիություններ,
- բարդ և անորոշ զույգեր։

Նույն dataset-ը պետք է փորձարկել չորս տարբերակով՝

1. սկաներների սկզբնական արդյունքներ,
2. deterministic deduplication,
3. մեկ մեծ deduplication prompt,
4. VulnFusion Structured LLM Dedup։

Պետք է պահպանել օգտագործված մոդելը, մուտքային տվյալները և ճիշտ պատասխանները,
որպեսզի մեկ այլ մարդ կարողանա կրկնել փորձը։

### Ինչ է ապացուցում ներկա evaluation-ը

Ներկա `utils.dedup_evaluation` թեստերը օգտագործում են Oracle client, որը գիտի
սպասվող ճիշտ խմբերը։ Սա օգտակար է․ այն ապացուցում է, որ candidate-ների
մշակումը, clustering-ը, provenance-ը և metrics-ը ճիշտ են աշխատում։

Բայց սա դեռ **չի ապացուցում**, որ իրական LLM-ը ավելի լավ որոշումներ է ընդունում։
Դրա համար անհրաժեշտ է վերևում նկարագրված առանձին live benchmark-ը։

### Ինչ պետք է ցույց տա լավ demo-ն

Report-ը պետք է ցույց տա պարզ համեմատություն։

```text
Սկաներների սկզբնական արդյունքներ   27 finding
Deterministic dedup                 22 finding
VulnFusion                          18 finding
                                    3 AI-confirmed խումբ
                                    2 finding պահանջում է ստուգում
```

Հետո demo-ն պետք է բացի երեք իրական օրինակ՝

- մեկ ճիշտ LLM միավորում,
- մեկ սխալ միավորում, որը VulnFusion-ը կանխել է,
- մեկ անորոշ զույգ, որն ուղարկվել է մարդու ստուգման։

Սա ավելի ուժեղ ապացույց է, քան միայն վերջնական finding-ների փոքր քանակ ցույց
տալը։
