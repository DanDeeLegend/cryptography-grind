"""Small English corpus used to learn letter statistics for the substitution-cipher attack.

Original text written for this lab (no copyrighted material). TEST_PASSAGES are kept separate so
attacks are always evaluated on text the statistics were not trained on.
"""

TRAIN = """
The study of secret writing has a long history, and most of it is a story of people who believed their
methods were stronger than they really were. A message that looks like nonsense to a casual reader can
still be unraveled by someone who knows how language behaves. Every language has habits. Some letters
appear far more often than others, certain pairs of letters travel together, and a handful of short words
make up most of what anyone writes. These habits survive any substitution, which is why simple ciphers
fail. When the first scholars noticed that the most common symbol in a message usually stood for the most
common letter, the age of easy secrecy ended. Modern engineers inherit that lesson. A system should remain
safe even if the attacker understands exactly how it works, because secrets that depend on obscurity tend
to leak. Keys must be long enough that searching through all of them takes longer than anyone can wait,
and they must be chosen at random, never from a pattern that a person might guess. In practice most
failures come from the way a design is used rather than from the mathematics beneath it. People reuse
passwords, forget to update old software, and trust devices that nobody has examined. Good security work
therefore begins with questions about people and process before it ever reaches algorithms. What are we
protecting, who would want it, and what would they be willing to do to get it? Once those answers are
written down, the choice of a cipher becomes much easier. Teams that practice this habit build systems
that are boring in the best possible way: they work, they are tested, and they behave the same way tomorrow
as they did today. Reading old reports about broken systems is a useful exercise. The details differ, yet
the same mistakes appear again and again, such as small key spaces, repeated nonces, missing checks, and
trust placed in the wrong party. Learning to spot these patterns early saves a great deal of trouble later.
The weather turned cold that evening, and the travelers gathered around the fire to share stories about
distant cities, long roads, and the strange customs of people they had met along the way. One of them
carried a small book filled with notes in a code of her own invention, and she delighted in showing how the
symbols could be read once the rule was known. Another traveler, who had spent years working with numbers,
listened carefully and then explained how he would try to read the notes without being told the rule. He
counted how often each symbol appeared, compared the counts with the frequencies he expected in ordinary
speech, and guessed that the most frequent symbol stood for the letter that comes up most often. From that
single guess the rest followed quickly, because every correct choice made the next one easier to see.
"""

TEST_PASSAGES = [
    # ~600 letters each, deliberately different topics from TRAIN
    """Gardens reward patience. A seed pushed into the soil in spring needs water, sunlight and time before
    anything appears, and impatient gardeners often dig it up to check on it, which only delays the result.
    The best growers keep simple notes about what they planted, where they planted it and how the weather
    behaved. After a few seasons those notes show which vegetables prefer shade, which flowers survive a dry
    summer and which corners of the yard stay wet long after the rain has stopped. With that knowledge a
    small plot can feed a family, attract bees and butterflies, and provide a quiet place to sit in the
    evening when the day's work is finished and the air smells of herbs and warm earth.""",
    """The railway reached the town late in the nineteenth century, and within a decade the whole character of
    the place had changed. Farmers who once carried grain to market by cart could now ship it to distant
    cities in a single afternoon. Shops opened along the main street, a telegraph office appeared near the
    station, and newcomers arrived with ideas about schools, newspapers and public libraries. Older residents
    complained about the noise and the smoke, yet few of them would have given up the convenience. Their
    children grew up expecting that the world was close at hand, and that expectation shaped every choice
    they later made about where to live and what to study.""",
    """Learning a musical instrument is mostly a matter of repetition done with attention. A student who plays a
    difficult passage slowly, listens to every note and corrects small mistakes will improve faster than one
    who rushes through the whole piece ten times. Teachers often recommend short daily sessions instead of a
    single long weekend practice, because the brain consolidates new skills during rest. Recording yourself
    is another useful habit. The first playback is usually humbling, but it reveals uneven rhythm, unclear
    phrasing and places where the tempo drifts, and these are exactly the details worth fixing before
    performing for an audience of friends or family.""",
]
