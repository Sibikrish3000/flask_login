import smtplib

server = smtplib.SMTP('smtp.gmail.com', 587)
server.starttls()

server.login('contact.sibikrish@gmail.com', 'yjns wcuy beqe yutc')
server.sendmail('contact.sibikrish@gmail.com', 'sibikrish2005@gmail.com', 'Test email')
server.quit()
