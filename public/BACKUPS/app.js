const STORAGE_KEY = "blog_auth_token";

const PUBLIC_ARTICLES = [
  {
    id: "a1",
    title: "How to write good articles (without fluff)",
    date: "2026-05-01",
    tags: ["writing", "blog"],
    image: {
      src: "/images/writing.svg",
      alt: "A stylized writing cover image",
      caption: "Clarity beats length: structure makes writing feel effortless.",
    },
    excerpt:
      "A useful article isn't long: it's clear. Here's a simple structure that reliably works.",
    body: [
      "Good writing isn't about being clever—it's about being understood. Before you write a single word, ask yourself: what will the reader be able to do, think, or decide after reading this? That question is your compass. If you can't answer it in one sentence, you're not ready to write yet.",
      "Start with a clear promise in the first paragraph. Don't bury the lead. Tell readers immediately what problem you're solving and why it matters to them. The first 30 words decide whether someone keeps reading or bounces. Make them count.",
      "Use headings that sound like answers, not like topics. Compare 'API caching' (a topic) vs 'How to cache safely without stale data' (an answer). Topic headings make readers work harder. Answer headings reward skimmers and build trust that the content will deliver.",
      "Make the middle concrete. One specific example is worth ten vague sentences. Show the input, the output, and the decision you made in between. If you can't give a concrete example, it's a sign your understanding of the topic isn't solid enough yet—and that's fine. Go learn it, then write.",
      "Transitions are the invisible glue of good writing. Each section should end by setting up why the next one matters. 'Now that you know the structure, let's talk about the editing process that keeps it lean.' That one sentence turns a list of ideas into a journey.",
      "Editing is where good writing actually happens. First drafts are for getting ideas out; editing is for making them clear. Use this rule: if a sentence doesn't move the reader forward or doesn't add something the reader didn't already know, delete it. Read your draft out loud—your ear catches awkwardness your eye misses.",
      "End with a tiny next step: a checklist, a template, or a single action to try today. Readers who finish an article and immediately do something are readers who come back. Don't end with a vague 'I hope this helps.' End with a direction.",
    ],
  },
  {
    id: "a2",
    title: "Blog design: fewer blocks, more reading",
    date: "2026-04-28",
    tags: ["ux", "design"],
    image: {
      src: "/images/design.svg",
      alt: "A layout-themed cover image",
      caption: "Great reading UX is mostly spacing, hierarchy, and contrast.",
    },
    excerpt:
      "Spacing, hierarchy, and typography: three details that change the reading experience.",
    body: [
      "Readers come for content, not chrome. The best blog design is the one that disappears. When someone reads an article, they should feel like they're in a conversation with the author—not navigating an interface. Every UI element that isn't helping the reader understand is competing with the content.",
      "Spacing is the most underrated design tool. It signals relationships: things that are close are related, things with space between them are separate. Cramped layouts feel anxious; generous spacing feels confident and easy. If your blog looks cluttered, try doubling the padding before you add any other design element.",
      "Pick one layout rhythm and stick to it. If your cards have 14px padding, don't randomly switch to 22px—consistency is what feels 'professional.' Your eye doesn't consciously notice consistent spacing, but it immediately notices inconsistency, and that distraction costs you reader trust.",
      "Hierarchy is a promise: the eye should know where to start and what matters most. Titles must be bold; metadata should be muted; body text should breathe. A strong visual hierarchy means a reader can skim your article and still understand its structure—that's respect for their time.",
      "Typography: avoid tiny fonts. Most blogs feel better at 15–18px with a line height around 1.5–1.7. Also watch line length—aim for 60–80 characters per line. Too narrow feels choppy; too wide forces the eye to travel far and makes it easy to lose your place on the next line.",
      "Color is a hierarchy tool, not just decoration. Dark backgrounds work beautifully for tech blogs if contrast ratios are respected. Use accent colors sparingly—one strong accent is memorable; five competing accents are noise. Muted secondary text helps the eye prioritize what's important.",
      "If you include a login or access panel, integrate it into the layout rather than dropping it on top as a modal barrier. A sidebar card or an inline section feels native to the reading experience. A fullscreen overlay feels like an interruption—and interruptions kill momentum.",
    ],
  },
  {
    id: "a3",
    title: "A quick checklist before publishing",
    date: "2026-04-20",
    tags: ["productivity"],
    image: {
      src: "/images/writing.svg",
      alt: "A simple cover illustration",
      caption: "Publishing quality becomes easy when it's a checklist.",
    },
    excerpt:
      "Review title, links, spelling, and a CTA. Publishing with quality is repeatable.",
    body: [
      "Before you hit publish, do a final pass with a checklist. It prevents 90% of avoidable issues without turning you into a perfectionist who never ships anything. The goal isn't perfection—it's preventing the obvious mistakes that erode reader trust.",
      "Title check: does it communicate a clear benefit? Would someone click on it if they saw it out of context? If you removed all adjectives, would it still be strong? Weak titles are usually the result of describing what you wrote about instead of what the reader gets out of it.",
      "Intro check: can someone understand the problem and the promise in 20 seconds? Read only the first three sentences. Does a stranger know why they should care? If not, your intro needs another pass.",
      "Skim test: scroll through your article as if you're a busy reader in a hurry. Are headings informative on their own? Could someone scroll through and still understand the structure of your argument? If the headings are vague or decorative, they're failing the reader.",
      "Links check: do all links open and point where you think they do? More importantly, does each link provide genuine additional context or evidence? If a link is there 'because it looks like I did research,' remove it. Every unnecessary link is a potential exit point.",
      "Readability check: read one paragraph out loud. If you run out of breath before the end of a sentence, that sentence is too long. If you stumble on a word, your readers will too. Plain language reads faster and feels smarter, not dumber.",
      "Call to action: invite a comment, a question, a share, or a small experiment to try. A CTA doesn't have to be aggressive—even 'Try this and let me know what happened' is enough to make someone feel part of a conversation rather than a passive audience.",
      "Finally: publish. Feedback is part of writing. An article that's live and slightly imperfect is infinitely more valuable than a perfect draft that no one sees. You can always update it later based on what readers actually ask.",
    ],
  },
  {
    id: "a4",
    title: "Simple authentication for private content",
    date: "2026-04-12",
    tags: ["web", "security"],
    image: {
      src: "/images/security.svg",
      alt: "A security-themed cover image",
      caption: "Demos can be simple; production needs strong defaults.",
    },
    excerpt:
      "A login inside the blog can unlock private sections without breaking the flow.",
    body: [
      "Authentication is a trust boundary: on one side, anyone; on the other, the people you've decided to let in. How you implement that boundary says a lot about how seriously you take your users' security—and their experience.",
      "For a demo or prototype, it's perfectly reasonable to store sessions in memory and keep a token in localStorage. It keeps the project easy to run, easy to understand, and easy to explain to collaborators. Just be explicit about the trade-offs so no one accidentally ships a prototype as production.",
      "In production, think in threat models, not just features. HTTPS is not optional—it's the baseline. Without it, tokens travel in plaintext over the network. Set cookies with HttpOnly and Secure flags so JavaScript can't read them and they can't travel over unencrypted connections.",
      "CSRF protection matters any time you use cookies. A forged request from another site can carry a valid session cookie. Use the SameSite cookie attribute and add a CSRF token for sensitive mutations. It's a few lines of middleware that eliminates a whole category of attack.",
      "Rate-limiting login endpoints is not optional—it's basic hygiene. Without it, an attacker can try thousands of passwords per minute. Limit attempts by IP address, add exponential backoff after failures, and lock accounts temporarily after repeated bad attempts. Log every failed login.",
      "Persistence matters. Sessions stored only in memory disappear on server restart—a poor experience for users and a debugging nightmare in production. Store sessions in a database like MySQL or a dedicated store like Redis. Both give you durability, search, and the ability to invalidate all sessions for a user.",
      "Rotate secrets. If your JWT secret or session key is compromised, an attacker can forge any token. Use environment variables for secrets, never hardcode them in source, and have a plan to rotate them without downtime. This project is structured so you can swap the in-memory store for MySQL without changing the UI.",
    ],
  },
  {
    id: "a5",
    title: "How to plan an article readers finish",
    date: "2026-03-30",
    tags: ["writing", "planning"],
    image: {
      src: "/images/writing.svg",
      alt: "A planning-themed cover image",
      caption: "Planning is what makes long posts feel short.",
    },
    excerpt:
      "Long-form works when it has a clear path: a reader can always answer 'where am I and what's next?'.",
    body: [
      "Most articles that fail do so because of planning problems, not writing problems. The prose is fine; the structure is a maze. A reader who can't answer 'where am I in this article and what comes next?' will stop reading—not because they're lazy, but because the article isn't respecting their time.",
      "Start with the reader outcome. Not 'I want to talk about X,' but 'after reading this, the reader will be able to do Y.' That shift—from what you want to say to what they need to know—changes every decision that follows. It's the difference between an essay and a guide.",
      "Write the outline as questions, not topics. Instead of 'Section 2: Planning,' write 'How do I choose what sections to include?' Questions are magnetic—they pull the reader forward because they promise an answer. Topic headings are inert; they describe; they don't invite.",
      "Add constraints. Limit yourself to three to five main sections. More than that and you're writing a book chapter, not an article. Constraints force you to prioritize: what absolutely needs to be here, and what belongs in a separate, linked piece?",
      "For each section, plan one concrete artifact: a code snippet, a checklist, a decision table, a real example, a mini template, or a before/after comparison. Concrete artifacts are what readers remember and share. Abstract explanations are what they forget.",
      "Add transitions last. Transitions are the secret to flow—they tell the reader why the next section matters and how it connects to what they just read. 'Now that you know how to structure the outline, let's talk about where most writers lose readers: the middle.' That one sentence does more work than a whole paragraph of content.",
      "Remove anything that doesn't support the outcome. The instinct when writing long posts is to add more. The discipline of editing long posts is to take away. Ask of every paragraph: does this directly help the reader achieve the stated outcome? If not, cut it or move it to a future article.",
    ],
  },
  {
    id: "a6",
    title: "A practical guide to content structure for teams",
    date: "2026-03-12",
    tags: ["teams", "documentation"],
    image: {
      src: "/images/design.svg",
      alt: "A team documentation cover image",
      caption: "Shared structure is the fastest way to improve quality across a team.",
    },
    excerpt:
      "If multiple people publish in one blog, consistency beats individual style. Use a shared template and clear rules.",
    body: [
      "When a blog has one author, style is personal. When a blog has five authors, style is chaos unless you make explicit what used to be intuitive. Teams don't need more meetings—they need shared defaults. A simple structure template makes every post easier to write, easier to edit, and easier to read.",
      "Start with a content template everyone can follow without thinking too hard. A reliable six-part structure: (1) Problem—what situation does this address? (2) Context—why does it matter now? (3) Approach—what's the recommended way to handle it? (4) Example—show it working in practice. (5) Pitfalls—what goes wrong and why? (6) Next steps—what should the reader do immediately after?",
      "Define your tone explicitly, not vaguely. 'Friendly and direct' is a start, but give examples. Show a sentence in the old voice and the new voice. Show what 'too formal' and 'too casual' look like. Concrete examples of tone are worth ten pages of abstract tone guidelines.",
      "Set formatting rules. Short paragraphs (3–5 sentences max). Headings for every major section. Bold only for genuinely important terms, not for decoration. Links only when they add context the article doesn't provide. One image per article minimum, captioned. These aren't arbitrary—they're the patterns that correlate with higher read-through rates.",
      "Create a peer review checklist: title clarity (can a stranger understand the benefit?), first paragraph promise (does it set up what the reader gets?), one strong concrete example (not hypothetical), and a closing action (what should they do right now?). A checklist takes two minutes to run and catches 80% of avoidable issues before publish.",
      "Track what performs. Which posts get the most comments? Which get shared internally? Which generate follow-up questions? Use that data to refine your template and your topics list. Teams that treat their blog as a knowledge product get better over time; teams that treat it as a content treadmill plateau.",
      "Over time, promote the best posts into internal standards. Your blog becomes a living knowledge base, not just a timeline. The article on code review process becomes the canonical reference. The guide on incident communication becomes the default template. When content compounds like that, it's an asset—not just an output.",
    ],
  },
  {
    id: "a7",
    title: "JavaScript performance: what actually matters",
    date: "2026-05-03",
    tags: ["web", "javascript", "performance"],
    image: {
      src: "/images/security.svg",
      alt: "A performance-themed cover image",
      caption: "Measure first. Most slowness isn't where you think it is.",
    },
    excerpt:
      "Most performance problems are caused by a handful of patterns. Here's what to look for and how to fix them.",
    body: [
      "JavaScript performance problems cluster around a small number of root causes. The developers who debug them fastest are the ones who know where to look first—not the ones who have memorized every micro-optimization trick. Measure before you optimize. Always.",
      "The first thing to profile is your main thread. Open DevTools, record a performance trace while the page is slow, and look at the flame chart. Most slowness lives in two places: long-running synchronous tasks that block the UI, and excessive DOM manipulation inside loops. Both are visible immediately in a trace.",
      "Long tasks (tasks over 50ms) are the primary enemy of perceived performance. They block the browser from responding to user input, which makes interfaces feel laggy even if they're technically doing important work. Break long tasks up with setTimeout, requestIdleCallback, or (for modern apps) the Scheduler API. Give the browser a chance to breathe between chunks of work.",
      "DOM operations are expensive—especially reads and writes mixed together. When you read a layout property (like offsetHeight) after writing to the DOM, you force the browser to recalculate styles synchronously. This is called layout thrashing. The fix is simple: batch your reads, then batch your writes. Never interleave them.",
      "Network is often the real bottleneck, not JavaScript execution. Before optimizing your code, check the Network tab. Are you loading more than you need? Are you making sequential requests that could be parallel? Are large images blocking the critical rendering path? A 300KB uncompressed image costs more than almost any JavaScript inefficiency.",
      "Memoization is a useful tool for expensive computations that are called repeatedly with the same arguments. But it's not magic—it trades CPU time for memory, and memory in a browser tab is not free. Memoize judiciously: computations that are actually expensive and actually repeated. Don't memoize everything because it sounds smart.",
      "Virtual DOM libraries like React do a good job of batching DOM updates, but they don't eliminate the need to think about rendering performance. Avoid unnecessary re-renders by keeping component state as local as possible, using stable references for callbacks and objects, and profiling with the React DevTools before assuming there's a problem.",
      "Finally, set a performance budget and hold to it. Decide: the page must be interactive within 2 seconds on a mid-range device on a 4G connection. Write that down. Run Lighthouse in CI. Treat a budget regression the same way you'd treat a test failure. Performance that isn't measured doesn't get maintained.",
    ],
  },
  {
    id: "a8",
    title: "REST vs GraphQL: choosing based on your actual needs",
    date: "2026-04-25",
    tags: ["web", "api", "architecture"],
    image: {
      src: "/images/design.svg",
      alt: "An API architecture cover image",
      caption: "Both work. The question is which fits your team and your data.",
    },
    excerpt:
      "Neither REST nor GraphQL is universally better. The right choice depends on your data shape, team size, and client diversity.",
    body: [
      "REST and GraphQL are both good solutions to the problem of getting data from a server to a client. The debates about which is 'better' are almost always the wrong debate. The right question is: which fits your specific situation? And the answer requires being honest about your data, your team, and your clients.",
      "REST is a great default. It's simple, cacheable, well-understood, and works with any HTTP client. For CRUD-heavy applications—where you're mostly reading, writing, updating, and deleting discrete resources—REST feels natural because the resources map directly to URLs. It's also easy to debug: open a browser, hit a URL, see JSON. That simplicity has enormous value.",
      "REST shows its limitations when clients need data that doesn't map neatly to resources. The canonical example: a mobile app that shows a user profile, their recent posts, and their follower count on one screen. That might require three REST calls—or one very fat endpoint that returns more than anyone needs. Either way, you're compromising.",
      "GraphQL solves the over-fetching and under-fetching problem elegantly. Clients declare exactly what they need, and the server returns exactly that—nothing more, nothing less. For teams with multiple clients (web, iOS, Android) with different data needs, GraphQL is a significant developer experience win. Each client team can evolve their queries without waiting on the API team.",
      "GraphQL also adds complexity. You need a schema, a resolver layer, query validation, and usually a separate tooling setup for documentation and playground. For small teams or projects where one team owns both the API and the client, that complexity often isn't worth it. The overhead of schema design and resolver logic can slow you down more than REST's limitations.",
      "Caching is a genuine REST advantage. HTTP caching is built into the protocol: CDNs, browsers, and proxies all understand GET requests. GraphQL typically uses POST for everything, which breaks standard HTTP caching. You can work around this with persisted queries or client-side caching libraries, but you're adding infrastructure that REST gives you for free.",
      "A practical decision framework: start with REST. If you find yourself building many custom endpoints to satisfy client needs, or if you have multiple clients with significantly different data requirements, evaluate GraphQL. If you're building a public API consumed by external developers, REST's simplicity and ubiquity is usually the right call. If you're building an internal API for a product with one or two clients, either works—pick what your team already knows.",
    ],
  },
  {
    id: "a9",
    title: "Writing documentation that developers actually read",
    date: "2026-04-05",
    tags: ["documentation", "developer experience"],
    image: {
      src: "/images/writing.svg",
      alt: "A documentation cover image",
      caption: "Good docs answer the question before the developer needs to ask it.",
    },
    excerpt:
      "Most documentation fails at the same four things. Here's a pattern that fixes all of them.",
    body: [
      "Documentation is a product. It has users (developers), it has a job to do (help them succeed faster), and it fails when it doesn't do that job—regardless of how thorough it is. The problem with most docs isn't that they're wrong; it's that they're written for the author's mental model, not the reader's questions.",
      "The most common documentation failure is starting with reference material instead of getting-started content. A new developer doesn't want to read a full API reference first—they want to see it work. Lead with a minimal working example. Show input and output. Let them run something before you explain how it works. The example is your hook.",
      "Tutorial vs. reference vs. guide: these are different documents with different jobs. A tutorial is sequential and goal-oriented—it holds your hand through accomplishing one thing. A reference is comprehensive and searchable—it covers every parameter, every return value. A guide is problem-oriented—'how do I do X?'—and sits between the two. Great docs have all three, clearly labeled.",
      "Code examples must run. This sounds obvious, but most documentation has examples that are incomplete, outdated, or require invisible prerequisites. Every example should be copy-pasteable and executable with minimal setup. If it requires environment variables, say so. If it requires a dependency, include the install command. Assume nothing.",
      "Error messages are documentation. When a developer hits an error, that's a documentation moment—they need information, and they need it now. Put the solution in the error message, or link directly to the relevant docs page. 'Invalid configuration' is not helpful. 'Invalid configuration: `port` must be a number, got string. See configuration guide: [link]' is helpful.",
      "Keep docs close to code. Docs that live in a separate repository drift. Every refactor that doesn't update the docs makes them slightly more wrong. The best teams treat doc changes as part of the definition of done for any feature—not a separate step. Enforce it in pull request templates: 'Did you update the documentation?'",
      "Measure documentation effectiveness. Ask: do developers find answers without asking questions in Slack? Does the number of support tickets decrease after doc improvements? Do new developers go from zero to productive faster? These are your KPIs. If you're not measuring, you're guessing. A/B test doc approaches the same way you'd A/B test product features.",
    ],
  },
  {
    id: "a10",
    title: "Building habits that make you a better developer over time",
    date: "2026-03-20",
    tags: ["career", "productivity", "learning"],
    image: {
      src: "/images/writing.svg",
      alt: "A career growth cover image",
      caption: "Small habits compound. The best developers aren't always the most talented—they're the most consistent.",
    },
    excerpt:
      "The developers who grow fastest aren't always the most talented. They practice specific habits that compound over time.",
    body: [
      "Technical skill in software development compounds like interest. The developers who are dramatically better at 40 than at 25 aren't usually more naturally gifted—they've been more deliberate. They've built habits that feed learning into their daily work, so improvement doesn't require carving out extra time. It just happens.",
      "Read code more than you write it. Most developers spend nearly all their reading time on their own codebase. The fastest way to expand your range is to read codebases you didn't write—open-source libraries you use, projects in languages you're learning, code reviews of colleagues outside your immediate team. Reading unfamiliar code develops pattern recognition that writing alone can't build.",
      "Write things down as you learn them. Not for others—for yourself. A private doc, a notes app, a local markdown file. The act of writing forces you to articulate what you actually understand vs. what you vaguely recognize. Six months later, your notes become a personal reference that's calibrated exactly to your gaps. It's the most underused learning tool available.",
      "Solve problems one level below your current abstraction. If you use a library, occasionally read its source. If you write SQL, occasionally read the query plan. If you use a framework, try building something without it. Understanding what's underneath doesn't mean you should always work at that level—but it changes the quality of the decisions you make above it.",
      "Timebox your debugging. When you've been stuck on a bug for 30 minutes, set a 15-minute timer and commit to asking for help when it rings. The instinct to keep going—'I'm almost there'—costs hours and breeds frustration. The act of explaining your problem to someone else (or to a rubber duck) forces clarity and often surfaces the answer. Ask for help earlier than feels comfortable.",
      "Invest in your tools. Not in the sense of buying the best laptop (though a comfortable keyboard matters)—in the sense of knowing your editor deeply. A developer who knows 50 keyboard shortcuts and custom snippets moves measurably faster than one who doesn't. Every time you do something repetitive by hand, ask: could a script, a macro, or a shortcut do this for me? Your future self will thank you.",
      "Teach what you're learning. Writing a blog post, giving a talk at a meetup, or explaining a concept to a junior colleague forces you to organize your knowledge, identify gaps, and find a way to communicate clearly. The teaching itself is the learning. Companies that have knowledge-sharing cultures (lunch-and-learns, internal blogs, documentation sprints) tend to level up their whole team faster as a result.",
    ],
  },
];

// Seed comments shown when MySQL is not configured
const SEED_COMMENTS = {
  a1: [
    { id: "s1a", name: "Laura M.", text: "The tip about headings that sound like answers completely changed how I write titles. I rewrote three drafts after reading this and they're so much stronger now.", createdAt: "2026-05-02T09:14:00Z" },
    { id: "s1b", name: "Daniel K.", text: "I've read dozens of 'how to write' articles and this is the first one that made me immediately open a draft and start editing. The 'read it out loud' rule is underrated.", createdAt: "2026-05-02T11:38:00Z" },
    { id: "s1c", name: "Priya S.", text: "The point about ending with a tiny next step is so obvious in retrospect, but I never thought to do it deliberately. Changed my last post and engagement went up noticeably.", createdAt: "2026-05-03T08:02:00Z" },
  ],
  a2: [
    { id: "s2a", name: "Tom R.", text: "The line length advice (60–80 chars) is something I ignored for years. Set it on my blog last week and the difference is night and day — it just feels easier to read.", createdAt: "2026-04-29T10:22:00Z" },
    { id: "s2b", name: "Camille D.", text: "Finally someone says it: login modals that interrupt the reading flow are awful. Sidebar integration is so much more respectful of the user's attention.", createdAt: "2026-04-30T14:55:00Z" },
    { id: "s2c", name: "Alex T.", text: "Bookmarked specifically for 'spacing is the most underrated design tool.' Going to paste this in front of every client that wants to cram more content above the fold.", createdAt: "2026-05-01T07:40:00Z" },
  ],
  a3: [
    { id: "s3a", name: "Sophie W.", text: "The skim test is my new favorite quality check. If your headings don't communicate the structure on their own, the article isn't ready. Simple but I'd never framed it that way.", createdAt: "2026-04-21T09:00:00Z" },
    { id: "s3b", name: "Marco B.", text: "I used to spend so long perfecting posts before publishing. This checklist gets me out the door without cutting corners. The 'publish, then iterate' mindset is healthier.", createdAt: "2026-04-22T16:33:00Z" },
  ],
  a4: [
    { id: "s4a", name: "James L.", text: "The section on CSRF and SameSite cookies is exactly the kind of practical security advice that's missing from most tutorials. They explain what, not why.", createdAt: "2026-04-13T11:10:00Z" },
    { id: "s4b", name: "Nina P.", text: "We shipped a demo app with in-memory sessions last year and immediately regretted it when the server restarted in prod. This article would have saved us 3 hours of debugging.", createdAt: "2026-04-14T08:47:00Z" },
    { id: "s4c", name: "Ricardo F.", text: "Rate-limiting logins is so often skipped in tutorials. Thanks for including it — it's not optional in anything real-world facing.", createdAt: "2026-04-15T13:21:00Z" },
  ],
  a5: [
    { id: "s5a", name: "Elena V.", text: "Writing outlines as questions instead of topics is such a small shift but it completely changes how you approach each section. I tried it yesterday and the article basically wrote itself.", createdAt: "2026-03-31T10:05:00Z" },
    { id: "s5b", name: "Chris H.", text: "The 3–5 sections constraint is good discipline. I keep writing outlines with 9 sections and then wondering why nothing gets finished. The constraint is the feature.", createdAt: "2026-04-01T14:18:00Z" },
  ],
  a6: [
    { id: "s6a", name: "Fatima A.", text: "We implemented the 6-part template (Problem, Context, Approach, Example, Pitfalls, Next steps) for our team blog three weeks ago. Quality is noticeably more consistent across authors.", createdAt: "2026-03-13T09:30:00Z" },
    { id: "s6b", name: "Ben O.", text: "The insight about promoting great posts into internal standards is undervalued. Our best retrospective became our default incident template. Saved hours.", createdAt: "2026-03-14T11:55:00Z" },
    { id: "s6c", name: "Sara N.", text: "Showing examples of tone instead of just describing it is advice I wish I'd seen before writing our style guide. Abstract tone guidelines get ignored; examples get followed.", createdAt: "2026-03-15T16:00:00Z" },
  ],
  a7: [
    { id: "s7a", name: "Lukas B.", text: "Layout thrashing was destroying our dashboard performance and we had no idea. One profiling session after reading this and we found three offenders in 20 minutes.", createdAt: "2026-05-04T08:12:00Z" },
    { id: "s7b", name: "Yuki T.", text: "The performance budget in CI idea is exactly what we needed. We set a Lighthouse budget threshold and it caught a regression in the next PR. Worth it immediately.", createdAt: "2026-05-04T13:44:00Z" },
    { id: "s7c", name: "Grace M.", text: "I always suspected memoization was being overused on our codebase. 'It trades CPU for memory and memory isn't free' — sending this to the team.", createdAt: "2026-05-05T09:20:00Z" },
  ],
  a8: [
    { id: "s8a", name: "Pedro A.", text: "The HTTP caching point is what tipped us toward REST for our public API. GraphQL's POST-everything approach would have meant redoing our CDN setup. Not worth it.", createdAt: "2026-04-26T10:30:00Z" },
    { id: "s8b", name: "Mei L.", text: "Finally a comparison that doesn't pick a side for ideological reasons. 'Start with REST, migrate if you feel the pain' is the only honest advice.", createdAt: "2026-04-27T14:02:00Z" },
  ],
  a9: [
    { id: "s9a", name: "Oliver G.", text: "Error messages as documentation hit hard. We rewrote 40 error strings last sprint to include the fix or a link. Support tickets dropped 30% in two weeks. Not joking.", createdAt: "2026-04-06T09:15:00Z" },
    { id: "s9b", name: "Aisha M.", text: "The tutorial vs reference vs guide distinction is something I wish every doc team would internalize. Mixing them up is why most docs feel confusing — you never know what you're reading.", createdAt: "2026-04-07T11:42:00Z" },
    { id: "s9c", name: "Patrick D.", text: "Docs close to code drift less — obvious once you say it, but we had our docs in a separate repo for two years and they were always 3 versions behind. Moved them last month.", createdAt: "2026-04-08T08:55:00Z" },
  ],
  a10: [
    { id: "s10a", name: "Hannah K.", text: "Reading code more than you write it is the habit I wish someone had told me at the start. I spent a month going through the Express source and learned more than in the previous year.", createdAt: "2026-03-21T09:00:00Z" },
    { id: "s10b", name: "Diego R.", text: "The 30-minute debugging timebox changed my week. I used to lose entire afternoons stuck on single bugs. Now I ask for help on time and it's almost always solved in 5 minutes.", createdAt: "2026-03-22T13:30:00Z" },
    { id: "s10c", name: "Lena S.", text: "Teaching what you're learning is real. I gave a 15-minute internal talk on something I'd just learned and realized halfway through I didn't actually understand two key parts. Fixed that fast.", createdAt: "2026-03-23T10:10:00Z" },
  ],
}

const MEMBERS_ARTICLES = [
  {
    id: "members-1",
    title: "Internal notes: blog roadmap",
    date: "2026-05-01",
    tags: ["internal", "roadmap"],
    image: {
      src: "/images/design.svg",
      alt: "Blog roadmap internal notes",
      caption: "Where this blog is going — and how we plan to get there.",
    },
    excerpt: "Ideas in progress: search, tags, editor workflow, and comments. This is the unfiltered version.",
    body: [
      "This is the living document behind the blog. Not polished, not final — just thinking out loud about where things are going and what's worth building next.",
      "Search is the most-requested feature. Right now the client-side filter works fine for ten articles, but it won't scale past fifty. The plan is a lightweight full-text index on the server — probably a simple MySQL FULLTEXT index on title, excerpt, and tags. No Elasticsearch, no external service. Keep it boring and maintainable.",
      "Tags need a proper taxonomy. Right now they're free-form strings, which means 'ux' and 'UX' are different tags, and 'web' is doing too much work. The fix is a controlled vocabulary: a fixed list of canonical tags, enforced at the API level, with a tag index page that lists all articles under each one.",
      "The editor workflow is the biggest gap. Publishing an article means editing a JavaScript array in app.js, which is fine for a solo blog but breaks immediately with multiple contributors. The roadmap here is a minimal admin panel — a protected route behind the editor role, with a form that writes to a database table instead of a source file. The public articles endpoint would then read from MySQL instead of a hardcoded array.",
      "Comments are technically working, but the UX needs work. There's no threading, no moderation queue, and no notification when someone replies. Short-term: add a basic moderation flag so editors can hide spam without deleting. Medium-term: email notifications for the article author when a new comment arrives.",
      "Performance is not a problem yet, but the architecture has one obvious future bottleneck: every page load fetches all public articles at once. When the article count grows, this should become a paginated endpoint — probably cursor-based pagination to keep it efficient even with filters applied.",
      "The member authentication system is intentionally minimal. The next step here is not adding OAuth (that's over-engineering for the current scale) but rather a proper password reset flow and the ability for admins to create new member accounts without editing source code.",
    ],
  }
];

const MEMBERS_SEED_COMMENTS = {
  "members-1": [
    { id: "ms1a", name: "Jordan P.", text: "The tag taxonomy point is long overdue. I keep tagging things 'web' and immediately regretting it because it's too broad to be useful. A controlled list would fix that fast.", createdAt: "2026-05-02T10:15:00Z" },
    { id: "ms1b", name: "Anika R.", text: "Cursor-based pagination is the right call. Offset pagination gets ugly fast when you add filters. Good to see it on the roadmap early rather than as a painful migration later.", createdAt: "2026-05-02T14:30:00Z" },
    { id: "ms1c", name: "Felix W.", text: "The admin panel idea makes sense. Even a dead-simple form that writes to the DB would be a massive quality-of-life improvement over editing JS arrays directly.", createdAt: "2026-05-03T09:05:00Z" },
  ],
};

function $(id) {
  return document.getElementById(id);
}

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatDate(iso) {
  try {
    const d = new Date(iso);
    return new Intl.DateTimeFormat("en-US", { year: "numeric", month: "short", day: "2-digit" }).format(d);
  } catch {
    return iso;
  }
}

function getToken() {
  return localStorage.getItem(STORAGE_KEY);
}

function setToken(token) {
  if (!token) localStorage.removeItem(STORAGE_KEY);
  else localStorage.setItem(STORAGE_KEY, token);
}

async function api(path, opts = {}) {
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(path, { ...opts, headers });
  const json = await res.json().catch(() => null);
  if (!res.ok) {
    const msg = json?.error || `HTTP ${res.status}`;
    throw new Error(msg);
  }
  return json;
}

function renderArticles(list) {
  const root = $("articles");
  root.innerHTML = "";
  for (const a of list) {
    const el = document.createElement("article");
    el.className = "card";
    el.style.cssText = "max-width:480px;width:100%;";
    el.innerHTML = `
      <h3 class="article-title">${escapeHtml(a.title)}</h3>
      <div class="article-meta">
        <span>${escapeHtml(formatDate(a.date))}</span>
        <span>•</span>
        <span>${escapeHtml(a.tags.join(", "))}</span>
      </div>
      <p class="article-excerpt">${escapeHtml(a.excerpt)}</p>
      <div class="article-actions">
        <button class="button primary" data-open="${escapeHtml(a.id)}">Read</button>
        <a class="link" href="#articulos">Save</a>
      </div>
    `;
    root.appendChild(el);
  }
}

async function fetchComments(articleId) {
  try {
    const res = await api(`/api/articles/${encodeURIComponent(articleId)}/comments`);
    if (Array.isArray(res.comments) && res.comments.length > 0) return res.comments;
    return SEED_COMMENTS[articleId] || [];
  } catch {
    // MySQL not configured — show seed comments
    return SEED_COMMENTS[articleId] || [];
  }
}

async function publishComment(articleId, { name, text }) {
  const res = await api(`/api/articles/${encodeURIComponent(articleId)}/comments`, {
    method: "POST",
    body: JSON.stringify({ name, text }),
  });
  return res.comment;
}

function renderComments(articleId, comments) {
  const root = document.querySelector(`[data-comments-root="${CSS.escape(articleId)}"]`);
  if (!root) return;

  if (!comments.length) {
    root.innerHTML = `<p class="muted" style="margin:0">No comments yet. Be the first!</p>`;
    return;
  }

  root.innerHTML = comments
    .map(
      (c) => `
    <div class="comment">
      <div class="comment-top">
        <strong>${escapeHtml(c.name || "Anonymous")}</strong>
        <span class="muted" style="font-size:12px">${escapeHtml(
          new Intl.DateTimeFormat("en-US", { year: "numeric", month: "short", day: "2-digit" }).format(
            new Date(c.createdAt)
          )
        )}</span>
      </div>
      <div class="comment-body">${escapeHtml(c.text)}</div>
    </div>
  `
    )
    .join("");
}

async function openModal(article) {
  $("modalTitle").textContent = article.title;
  $("modalMeta").textContent = `${formatDate(article.date)} · ${article.tags.join(", ")}`;

  const coverHtml = article.image
    ? `<figure class="article-cover">
        <img src="${escapeHtml(article.image.src)}" alt="${escapeHtml(article.image.alt)}" loading="lazy" />
        ${article.image.caption ? `<figcaption class="muted">${escapeHtml(article.image.caption)}</figcaption>` : ""}
      </figure>`
    : "";

  const bodyHtml = (article.body || []).map((p) => `<p>${escapeHtml(p)}</p>`).join("");

  let comments = [];
  try {
    comments = await fetchComments(article.id);
  } catch {
    // comments not available (MySQL not configured)
  }

  const commentCount = comments.length;
  const commentsHtml = `
    <div class="comments">
      <div class="comments-title">
        <h3 style="margin:0">Comments</h3>
        <span class="badge">${commentCount} ${commentCount === 1 ? "comment" : "comments"}</span>
      </div>
      <form class="form" data-comment-form="${escapeHtml(article.id)}">
        <label class="label">
          Name
          <input class="input" name="name" autocomplete="name" placeholder="Your name (optional)" />
        </label>
        <label class="label">
          Comment
          <textarea class="input" name="text" rows="4" placeholder="Write a comment..." required></textarea>
        </label>
        <button class="button primary" type="submit">Publish comment</button>
        <p class="muted" data-comment-error="${escapeHtml(article.id)}" style="margin: 0"></p>
      </form>
      <div class="comments-list" data-comments-root="${escapeHtml(article.id)}"></div>
    </div>
  `;

  $("modalBody").innerHTML = `${coverHtml}${bodyHtml}${commentsHtml}`;
  $("modalBody").dataset.articleId = article.id;
  renderComments(article.id, comments);

  $("modal").classList.remove("hidden");
  document.body.style.overflow = "hidden";
}

function closeModal() {
  $("modal").classList.add("hidden");
  document.body.style.overflow = "";
}

const WELCOME_MESSAGES = [
  {
    title: "Welcome back. You're in.",
    body: "You've got access to everything this blog has to offer. The members section is unlocked — enjoy the internal notes, early drafts, and content that doesn't make it to the public feed.",
  },
  {
    title: "Good to see you again.",
    body: "Members area is all yours. This is where the unfiltered stuff lives — roadmap notes, editorial experiments, and ideas that are still being tested before going public.",
  },
  {
    title: "You made it in.",
    body: "Not everyone gets here. The members section holds the drafts, the behind-the-scenes thinking, and the kind of content that's too raw or too specific for the main feed. Dig in.",
  },
  {
    title: "Access granted.",
    body: "The locked section is now open. You'll find internal notes and early-stage content that isn't ready for the public yet — or might never be. Consider yourself part of the inner circle.",
  },
  {
    title: "Hey, you're logged in.",
    body: "That means the good stuff is accessible. Member articles are below — they cover things we're still figuring out, which makes them more interesting than the polished public ones.",
  },
];

const RANDOM_TIPS = [
  "Members-only articles are published without the usual editing pass. What you read here is closer to thinking out loud than finished writing.",
  "You can leave comments on any public article without being logged in — but being a member means you get to see the context behind each one.",
  "The members section updates before the public feed. If something appears here, it's still being tested — your feedback actually shapes whether it gets published.",
  "Session tokens are stored in your browser and last 8 hours. You won't need to log in again unless you close the tab or sign out manually.",
  "Every article you see in the members area started as a private note. Some of them will never graduate to the public blog. You're seeing the raw version.",
  "The search bar on the home page only searches public articles. Members content is separate — scroll down to find it after logging in.",
  "If you share a members-only idea with someone, they'll need to log in to see the full article. Public excerpts are visible to everyone.",
];

function getRandomWelcome() {
  return WELCOME_MESSAGES[Math.floor(Math.random() * WELCOME_MESSAGES.length)];
}

function getRandomTip() {
  return RANDOM_TIPS[Math.floor(Math.random() * RANDOM_TIPS.length)];
}

function setAuthUI({ user }) {
  const badge = $("badge");
  const membersSection = $("miembros");
  const membersArea = $("membersArea");
  const membersLocked = $("membersLocked");
  const membersHint = $("membersHint");
  const loginBtn = $("loginBtn");
  const logoutBtn = $("logoutBtn");

  const loggedIn = Boolean(user);
  badge.textContent = loggedIn ? "Signed in" : "Not signed in";
  badge.classList.toggle("ok", loggedIn);

  loginBtn.disabled = loggedIn;
  loginBtn.classList.toggle("hidden", loggedIn);
  logoutBtn.disabled = !loggedIn;
  logoutBtn.classList.toggle("hidden", !loggedIn);

  // Hide the entire form fields when logged in, show when logged out
  const usernameLabel = $("username").closest("label") || $("username").parentElement;
  const passwordLabel = $("password").closest("label") || $("password").parentElement;
  if (usernameLabel) usernameLabel.classList.toggle("hidden", loggedIn);
  if (passwordLabel) passwordLabel.classList.toggle("hidden", loggedIn);



  if (membersSection) membersSection.classList.toggle("hidden", !loggedIn);
  membersArea.classList.toggle("hidden", !loggedIn);
  membersLocked.classList.toggle("hidden", loggedIn);

  const membersWelcome = $("membersWelcome");
  if (membersWelcome) {
    membersWelcome.classList.toggle("hidden", !loggedIn);
    if (loggedIn) {
      const welcome = getRandomWelcome();
      $("welcomeTitle").textContent = welcome.title;
      $("welcomeText").textContent = welcome.body;
      $("randomTip").textContent = getRandomTip();
    }
  }
}

function setError(msg) {
  const el = $("loginError");
  if (!msg) {
    el.textContent = "";
    el.classList.add("hidden");
    return;
  }
  el.textContent = msg;
  el.classList.remove("hidden");
}

async function refreshMe() {
  const token = getToken();
  if (!token) {
    setAuthUI({ user: null });
    return;
  }
  try {
    const me = await api("/api/me");
    setAuthUI({ user: me.user });
    await loadMembersArticles();
  } catch {
    setToken(null);
    setAuthUI({ user: null });
  }
}

async function fetchMembersComments(articleId) {
  try {
    const res = await api(`/api/articles/${encodeURIComponent(articleId)}/comments`);
    if (Array.isArray(res.comments) && res.comments.length > 0) return res.comments;
    return MEMBERS_SEED_COMMENTS[articleId] || [];
  } catch {
    return MEMBERS_SEED_COMMENTS[articleId] || [];
  }
}

async function openMembersModal(article) {
  $("modalTitle").textContent = article.title;
  $("modalMeta").textContent = `${formatDate(article.date)} · ${article.tags.join(", ")} · Members only`;

  const coverHtml = article.image
    ? `<figure class="article-cover">
        <img src="${escapeHtml(article.image.src)}" alt="${escapeHtml(article.image.alt)}" loading="lazy" />
        ${article.image.caption ? `<figcaption class="muted">${escapeHtml(article.image.caption)}</figcaption>` : ""}
      </figure>`
    : "";

  const bodyHtml = (article.body || []).map((p) => `<p>${escapeHtml(p)}</p>`).join("");

  let comments = [];
  try { comments = await fetchMembersComments(article.id); } catch {}

  const commentCount = comments.length;
  const commentsHtml = `
    <div class="comments">
      <div class="comments-title">
        <h3 style="margin:0">Comments</h3>
        <span class="badge">${commentCount} ${commentCount === 1 ? "comment" : "comments"}</span>
      </div>
      <form class="form" data-comment-form="${escapeHtml(article.id)}">
        <label class="label">
          Name
          <input class="input" name="name" autocomplete="name" placeholder="Your name (optional)" />
        </label>
        <label class="label">
          Comment
          <textarea class="input" name="text" rows="4" placeholder="Write a comment..." required></textarea>
        </label>
        <button class="button primary" type="submit">Publish comment</button>
        <p class="muted" data-comment-error="${escapeHtml(article.id)}" style="margin:0"></p>
      </form>
      <div class="comments-list" data-comments-root="${escapeHtml(article.id)}"></div>
    </div>
  `;

  $("modalBody").innerHTML = `${coverHtml}${bodyHtml}${commentsHtml}`;
  $("modalBody").dataset.articleId = article.id;
  renderComments(article.id, comments);

  $("modal").classList.remove("hidden");
  document.body.style.overflow = "hidden";
}

async function loadMembersArticles() {
  const root = $("membersArea");
  root.innerHTML = "";
  root.style.cssText = "display:flex;justify-content:center;";
  for (const a of MEMBERS_ARTICLES) {
    const el = document.createElement("article");
    el.className = "card";
    el.style.cssText = "max-width:480px;width:100%;";
    el.innerHTML = `
      <h3 class="article-title">${escapeHtml(a.title)}</h3>
      <div class="article-meta">
        <span>${escapeHtml(formatDate(a.date))}</span>
        <span>•</span>
        <span>${escapeHtml(a.tags.join(", "))}</span>
      </div>
      <p class="article-excerpt">${escapeHtml(a.excerpt)}</p>
      <div class="article-actions">
        <button class="button primary" data-open-member="${escapeHtml(a.id)}">Read</button>
      </div>
    `;
    root.appendChild(el);
  }
}

function wireEvents() {
  $("loginForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    setError(null);

    const username = $("username").value.trim();
    const password = $("password").value;
    if (!username || !password) return setError("Please enter username and password.");

    try {
      const res = await api("/api/login", { method: "POST", body: JSON.stringify({ username, password }) });
      setToken(res.token);
      $("password").value = "";
      await refreshMe();
    } catch (err) {
      setError(err.message || "Sign-in failed.");
    }
  });

  $("logoutBtn").addEventListener("click", async () => {
    setError(null);
    try {
      await api("/api/logout", { method: "POST" });
    } catch {
      // ignore
    }
    setToken(null);
    $("username").value = "";
    $("password").value = "";
    $("membersArea").innerHTML = "";
    setAuthUI({ user: null });
  });

  document.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-open]");
    if (btn) {
      const id = btn.getAttribute("data-open");
      const a = PUBLIC_ARTICLES.find((x) => x.id === id);
      if (a) openModal(a);
      return;
    }

    const memberBtn = e.target.closest("[data-open-member]");
    if (memberBtn) {
      const id = memberBtn.getAttribute("data-open-member");
      const a = MEMBERS_ARTICLES.find((x) => x.id === id);
      if (a) openMembersModal(a);
      return;
    }

    const close = e.target.closest("[data-close]");
    if (close) closeModal();
  });

  document.addEventListener("submit", async (e) => {
    const form = e.target.closest("[data-comment-form]");
    if (!form) return;
    e.preventDefault();

    const articleId = form.getAttribute("data-comment-form");
    if (!articleId) return;

    const errEl = document.querySelector(`[data-comment-error="${CSS.escape(articleId)}"]`);
    if (errEl) errEl.textContent = "";

    const fd = new FormData(form);
    const name = String(fd.get("name") || "").trim().slice(0, 60);
    const text = String(fd.get("text") || "").trim().slice(0, 2000);
    if (!text) return;

    try {
      await publishComment(articleId, { name, text });
      form.reset();
      const comments = await fetchComments(articleId);
      renderComments(articleId, comments);
      const badge = document.querySelector(".comments .badge");
      if (badge) {
        const n = comments.length;
        badge.textContent = `${n} ${n === 1 ? "comment" : "comments"}`;
      }
    } catch (err) {
      if (errEl) errEl.textContent = err?.message || "Could not publish comment.";
    }
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeModal();
  });

  $("search").addEventListener("input", (e) => {
    const q = String(e.target.value || "").trim().toLowerCase();
    const filtered = !q
      ? PUBLIC_ARTICLES
      : PUBLIC_ARTICLES.filter((a) => {
          const hay = `${a.title} ${a.excerpt} ${a.tags.join(" ")}`.toLowerCase();
          return hay.includes(q);
        });
    renderArticles(filtered);
  });
}

function init() {
  renderArticles(PUBLIC_ARTICLES);
  wireEvents();
  refreshMe();
}

init();