from caloriesapi.models import Calorie
import django_filters


class MyModelFilter(django_filters.FilterSet):
    # article = django_filters.CharFilter(field_name='relationship__name', lookup_expr='contains')

    class Meta:
        model = Calorie
        # Declare all your model fields by which you will filter
        # your queryset here:
        fields = ['id', 'calorie', 'meals', 'calorie_note', 'calorie_per_day']