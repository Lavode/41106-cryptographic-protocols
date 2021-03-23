library(ggplot2)
library(dplyr)

df = read.csv("../data/performance.csv")
df$duration_s = df$duration_ms / 1000
df$keyid = factor(df$keyid)
levels(df$keyid) = list("|q| = 160, |p| = 1024" = "q=160,p=1024", "|q| = 256, |p| = 2048" = "q=256,p=2048")

summary = df %>% group_by(keyid, exponent) %>% summarize(avg_duration = mean(duration_s), n = n(), sd = sd(duration_s))

ggplot(summary, aes(x = exponent, y = avg_duration, color = keyid)) + 
  geom_point() +
  geom_line() +
  # geom_errorbar(aes(ymin = avg_duration - sd, ymax = avg_duration + sd)) +
  scale_y_log10() +
  theme_minimal() +
  labs(y = "Average decryption duration [s]", x = "Order of magnitude of plaintext", color = "Key parameters") +
  ggsave("../elgamal_performance.png", width = 20, units = 'cm', dpi = 'print')
  
  
  