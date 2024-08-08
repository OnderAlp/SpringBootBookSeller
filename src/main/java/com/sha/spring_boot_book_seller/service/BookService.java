package com.sha.spring_boot_book_seller.service;

import com.sha.spring_boot_book_seller.controller.AuthenticationController;
import com.sha.spring_boot_book_seller.model.Book;
import com.sha.spring_boot_book_seller.repository.IBookRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class BookService implements IBookService
{
    private final IBookRepository bookRepository;

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationController.class);

    public BookService(IBookRepository bookRepository) {
        this.bookRepository = bookRepository;
    }

    @Override
    public Book saveBook(Book book)
    {
        logger.error("Book Service saveBook");
        book.setCreateTime(LocalDateTime.now());
        return bookRepository.save(book);
    }

    @Override
    public void deleteBook(Long id)
    {
        bookRepository.deleteById(id);
    }

    @Override
    public List<Book> findAllBooks()
    {
        return bookRepository.findAll();
    }
}
