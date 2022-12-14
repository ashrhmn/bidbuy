package dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import model.User;

import java.util.List;
import java.util.stream.Collectors;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UserDto {

    private int id;

    private int nid;

    private KycDto kyc;

    private String email;

    private String username;

//    private String password;

    private String type;

    private List<ProductDto> soldProducts;
    private List<ProductDto> boughtProducts;
    private boolean isEmailVerified;


    public static UserDto fromDb(User user) {
        return user == null ? null : new UserDto(
                user.getId(),
                user.getNid(),
                null,
                user.getEmail(),
                user.getUsername(),
//                user.getPassword(),
                user.getType(),
                null,
                null,
                user.isEmailVerified()
        );
    }

    public static UserDto fromDbWithRelations(User user) {
        UserDto userDto = UserDto.fromDb(user);
        if (userDto == null) return null;
        userDto.setSoldProducts(user.getSoldProducts().stream().map(ProductDto::fromDb).collect(Collectors.toList()));
        userDto.setBoughtProducts(user.getBoughtProducts().stream().map(ProductDto::fromDb).collect(Collectors.toList()));
        userDto.setKyc(KycDto.fromDb(user.getKyc()));
        return userDto;
    }

}
