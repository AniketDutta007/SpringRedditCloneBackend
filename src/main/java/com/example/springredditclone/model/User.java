package com.example.springredditclone.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity(name = "user")
@Table(name = "reddit_user")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private Name name;
    @Column(unique = true)
    private String username;
    private String password;
    @Column(unique = true)
    private String email;
    private Instant created;
    private boolean enabled;
    @OneToMany(mappedBy = "user", fetch = FetchType.LAZY)
    private List<Post> posts;
    @OneToMany(mappedBy = "user", fetch = FetchType.LAZY)
    private List<Vote> votes;
    @OneToMany(mappedBy = "user", fetch = FetchType.LAZY)
    private List<Comment> comments;
    @OneToMany(mappedBy = "user", fetch = FetchType.LAZY)
    private List<Subreddit> subreddits;
    @OneToMany(mappedBy = "user")
    private List<RefreshToken> refreshTokens;
}
