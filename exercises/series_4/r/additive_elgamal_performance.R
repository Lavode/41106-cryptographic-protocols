library(ggplot2)
library(dplyr)

df = read.csv("../data/performance.csv")
summary = df %>% group_by(keyid, exponent) %>% summarize(avg_duration = mean(duration_ms), n = n(), sd = sd(duration_ms))

ggplot(summary, aes(x = exponent, y = avg_duration)) + 
  scale_y_log10() +
  labs(y = "Average duration [ms]", x = "Exponent size", title = "Performance of additively homomorphic ElGamal") + 
  geom_line()
