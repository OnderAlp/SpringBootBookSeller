package com.sha.spring_boot_book_seller.controller;

import com.sha.spring_boot_book_seller.model.Book;
import com.sha.spring_boot_book_seller.service.IBookService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/book")
public class BookController
{
    @Autowired
    private IBookService bookService;

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationController.class);

    @PostMapping // api/book
    public ResponseEntity<?> saveBook(@RequestBody Book book)
    {
        logger.error("Book Controller save book");
        return new ResponseEntity<>(bookService.saveBook(book), HttpStatus.CREATED);
    }

    @DeleteMapping("{bookId}")
    public ResponseEntity<?> deleteBook(@PathVariable Long bookId)
    {
        bookService.deleteBook(bookId);

        return new ResponseEntity<>(HttpStatus.OK);
    }

    @GetMapping // api/book
    public ResponseEntity<?> getAllBooks()
    {
        return new ResponseEntity<>(bookService.findAllBooks(), HttpStatus.OK);
    }
}
